//go:build windows

package mcpprocess

import (
	"errors"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type accountingInfo struct {
	TotalUserTime, TotalKernelTime                                                 int64
	ThisPeriodTotalUserTime, ThisPeriodTotalKernelTime                             int64
	TotalPageFaultCount, TotalProcesses, ActiveProcesses, TotalTerminatedProcesses uint32
}

func startTree(cmd *exec.Cmd) (func() error, func() error, error) {
	job, err := newKillOnCloseJob()
	if err != nil {
		return nil, nil, err
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.CREATE_SUSPENDED}
	if err = cmd.Start(); err != nil {
		_ = windows.CloseHandle(job)
		return nil, nil, err
	}
	abort := func(cause error) (func() error, func() error, error) {
		_ = windows.TerminateJobObject(job, 1)
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		_ = windows.CloseHandle(job)
		return nil, nil, cause
	}
	pid, err := windowsProcessID(cmd.Process.Pid)
	if err != nil {
		return abort(err)
	}
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return abort(err)
	}
	if err = windows.AssignProcessToJobObject(job, process); err != nil {
		_ = windows.CloseHandle(process)
		return abort(err)
	}
	if err = windows.CloseHandle(process); err != nil {
		return abort(err)
	}
	thread, err := primaryThread(pid)
	if err != nil {
		return abort(err)
	}
	count, resumeErr := windows.ResumeThread(thread)
	closeErr := windows.CloseHandle(thread)
	if resumeErr != nil || closeErr != nil || count != 1 {
		return abort(errors.Join(resumeErr, closeErr, unexpectedCount(count)))
	}
	var mu sync.Mutex
	kill := func() error {
		mu.Lock()
		defer mu.Unlock()
		var info accountingInfo
		// #nosec G103 -- x/sys/windows accepts uintptr; the synchronous API writes the basic job accounting structure.
		if err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)), nil); err != nil {
			return err
		}
		if info.ActiveProcesses == 0 {
			return nil
		}
		if err := windows.TerminateJobObject(job, 1); err != nil {
			return errors.Join(err, cmd.Process.Kill())
		}
		return nil
	}
	finish := func() error { return windows.CloseHandle(job) }
	return kill, finish, nil
}

func newKillOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	// #nosec G103 -- x/sys/windows accepts uintptr; the synchronous API reads this initialized, blittable job limit structure.
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return 0, errors.Join(err, windows.CloseHandle(job))
	}
	return job, nil
}

func primaryThread(pid uint32) (handle windows.Handle, err error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return 0, err
	}
	defer func() {
		closeErr := windows.CloseHandle(snapshot)
		if closeErr != nil && handle != 0 {
			closeErr = errors.Join(closeErr, windows.CloseHandle(handle))
			handle = 0
		}
		err = errors.Join(err, closeErr)
	}()
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	if firstErr := windows.Thread32First(snapshot, &entry); firstErr != nil {
		return 0, firstErr
	}
	var id uint32
	for {
		if entry.OwnerProcessID == pid {
			if id != 0 {
				return 0, errors.New("MCP process started with multiple suspended threads")
			}
			id = entry.ThreadID
		}
		err = windows.Thread32Next(snapshot, &entry)
		if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
			break
		}
		if err != nil {
			return 0, err
		}
	}
	if id == 0 {
		return 0, errors.New("MCP process primary thread was not found")
	}
	return windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, id)
}

func windowsProcessID(pid int) (uint32, error) {
	if pid <= 0 || uint64(pid) > uint64(^uint32(0)) {
		return 0, errors.New("MCP process ID is outside the Windows process ID range")
	}
	return uint32(pid), nil
}

func unexpectedCount(count uint32) error {
	if count == 1 {
		return nil
	}
	return errors.New("MCP process primary thread was not suspended exactly once")
}
