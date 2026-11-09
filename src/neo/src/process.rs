use std::io;
use std::process::{Child, Command};

#[cfg(target_os = "windows")]
mod platform {
    use super::*;
    use std::mem::size_of;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject,
    };
    use windows_sys::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
    };

    struct Handle(HANDLE);

    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    pub struct ProcessTree(Handle);

    impl ProcessTree {
        pub fn spawn(command: &mut Command) -> io::Result<(Child, Self)> {
            let job = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if job.is_null() {
                return Err(io::Error::last_os_error());
            }
            let tree = Self(Handle(job));
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if unsafe {
                SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            // Assign the suspended child before it can create descendants outside the job.
            let mut child = command
                .creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW)
                .spawn()?;
            let setup = (|| {
                if unsafe { AssignProcessToJobObject(job, child.as_raw_handle()) } == 0 {
                    return Err(io::Error::last_os_error());
                }
                let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
                if snapshot == INVALID_HANDLE_VALUE {
                    return Err(io::Error::last_os_error());
                }
                let snapshot = Handle(snapshot);
                let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
                entry.dwSize = size_of::<THREADENTRY32>() as u32;
                let mut found = unsafe { Thread32First(snapshot.0, &mut entry) };
                while found != 0 {
                    if entry.th32OwnerProcessID == child.id() {
                        let thread =
                            unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, entry.th32ThreadID) };
                        if thread.is_null() {
                            return Err(io::Error::last_os_error());
                        }
                        let thread = Handle(thread);
                        if unsafe { ResumeThread(thread.0) } == u32::MAX {
                            return Err(io::Error::last_os_error());
                        }
                        return Ok(());
                    }
                    found = unsafe { Thread32Next(snapshot.0, &mut entry) };
                }
                Err(io::Error::other(
                    "failed to find the suspended process thread",
                ))
            })();
            if let Err(error) = setup {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
            Ok((child, tree))
        }

        pub fn terminate(&self) -> io::Result<()> {
            if unsafe { TerminateJobObject(self.0.0, 1) } == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(unix)]
mod platform {
    use super::*;
    use std::os::unix::process::CommandExt;

    pub struct ProcessTree(libc::pid_t);

    impl ProcessTree {
        pub fn spawn(command: &mut Command) -> io::Result<(Child, Self)> {
            let child = command.process_group(0).spawn()?;
            let tree = Self(child.id() as libc::pid_t);
            Ok((child, tree))
        }

        pub fn terminate(&self) -> io::Result<()> {
            if unsafe { libc::kill(-self.0, libc::SIGKILL) } == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                Ok(())
            } else {
                Err(error)
            }
        }
    }

    impl Drop for ProcessTree {
        fn drop(&mut self) {
            let _ = self.terminate();
        }
    }
}

pub use platform::ProcessTree;
