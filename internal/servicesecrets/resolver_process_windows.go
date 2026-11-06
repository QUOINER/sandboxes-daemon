//go:build windows

package servicesecrets

import (
	"context"
	"errors"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func hostShellCommand(ctx context.Context, command string) *exec.Cmd {
	//nolint:gosec // Explicit --command source is user-approved host shell text; process execution stays bounded and on the host.
	return exec.CommandContext(ctx, "cmd.exe", "/d", "/s", "/c", command)
}

type resolverJobAccountingInfo struct {
	TotalUserTime, TotalKernelTime                       int64
	ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime   int64
	TotalPageFaultCount, TotalProcesses, ActiveProcesses uint32
	TotalTerminatedProcesses                             uint32
}

func startResolverProcess(command *exec.Cmd) (func() error, func() error, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, nil, err
	}
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		_ = windows.CloseHandle(job)
		return nil, nil, err
	}
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}
	if err := command.Start(); err != nil {
		_ = windows.CloseHandle(job)
		return nil, nil, err
	}
	abort := func(startErr error) (func() error, func() error, error) {
		_ = windows.TerminateJobObject(job, 1)
		_ = command.Process.Kill()
		_ = windows.CloseHandle(job)
		_ = command.Wait()
		return nil, nil, startErr
	}
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(command.Process.Pid))
	if err != nil {
		return abort(err)
	}
	if err := windows.AssignProcessToJobObject(job, process); err != nil {
		_ = windows.CloseHandle(process)
		return abort(err)
	}
	if err := windows.CloseHandle(process); err != nil {
		return abort(err)
	}
	thread, err := suspendedPrimaryThread(uint32(command.Process.Pid))
	if err != nil {
		return abort(err)
	}
	previousSuspendCount, resumeErr := windows.ResumeThread(thread)
	closeThreadErr := windows.CloseHandle(thread)
	if resumeErr != nil || closeThreadErr != nil || previousSuspendCount != 1 {
		return abort(errors.Join(resumeErr, closeThreadErr, unexpectedSuspendCount(previousSuspendCount)))
	}
	var terminateMu sync.Mutex
	terminate := func() error {
		terminateMu.Lock()
		defer terminateMu.Unlock()
		var info resolverJobAccountingInfo
		if err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation,
			uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil); err != nil {
			return err
		}
		if info.ActiveProcesses == 0 {
			return nil
		}
		return windows.TerminateJobObject(job, 1)
	}
	cleanup := func() error {
		terminateErr := terminate()
		closeErr := windows.CloseHandle(job)
		return errors.Join(terminateErr, closeErr)
	}
	return terminate, cleanup, nil
}

func suspendedPrimaryThread(processID uint32) (windows.Handle, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	if err := windows.Thread32First(snapshot, &entry); err != nil {
		return 0, err
	}
	threadID := uint32(0)
	for {
		if entry.OwnerProcessID == processID {
			if threadID != 0 {
				return 0, errors.New("secret resolver started with multiple suspended threads")
			}
			threadID = entry.ThreadID
		}
		err := windows.Thread32Next(snapshot, &entry)
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			break
		}
		if err != nil {
			return 0, err
		}
	}
	if threadID == 0 {
		return 0, errors.New("secret resolver primary thread was not found")
	}
	thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, threadID)
	if err != nil {
		return 0, err
	}
	return thread, nil
}

func unexpectedSuspendCount(previous uint32) error {
	if previous == 1 {
		return nil
	}
	return errors.New("secret resolver primary thread was not suspended exactly once")
}
