# check_ms_win_files
Nagios NCPA plugin to check presence and size of files or folders

Syntax:
	check_ms_win_files.ps1 -f filename [ -ae ] [ -ane ] [ -w threshold ] [ -c threshold ]
	
Arguments:
  -f   | --File            => Full path of file or folder to check (mandatory).
  -ae  | --AlertOnExist    => Throw CRITICAL alert if file/folder exists.
  -ane | --AlertOnNotExist => Throw CRITICAL alert if file/folder doesn't exist.
  -w   | --Warning         => Size threshold for warning alert (0 if omitted).
  -c   | --Critical        => Size threshold for critical alert (0 if omitted).
  -h   | --Help            => Print this help output.

Filename argument:

  In case file name contains spaces, it should be enclosed in single quotes, as
  it appears that it's the best way to provide argument to PowerShell scripts
  (see https://github.com/NagiosEnterprises/ncpa/issues/363).
  
  File name CANNOT CONTAIN accented or other strange characters for the moment,
  I don't manage to send these in the argument (é, à, ç, etc.)

Threshold arguments:

  threshold ::= size [ unit ] [ reverse ] (all glued together, no space)
  size      ::= <positive number>
  unit      ::= <size multiplier among k, M, G, T, ki, Mi, Gi, Ti>
  reverse   ::= : (colon means alert is raised if the file size is <= threshold)
                  (empty means alert is raised if the file size is >= threshold)

  NB: Folder size is always equal to 1 byte, and does not represent the sum of
      contained files' size.

Examples:
  -w 4M -c 5M   (warning if >= 4000000 bytes, critical if >= 5000000 bytes)
  -w 4ki: -c 0: (warning if <= 4096 bytes, critical if zero)

Installation:
  Copy the check_ms_win_files.ps1 file in the plugins folder of your NCPA
  installation (typical path is "C:\Program Files (x86)\Nagios\NCPA\plugins").
  You may encounter problems in some Windows versions to execute it, in that
  case, here are two common things to do:
  
  1. Change Powershell execution policy to Remote Signed:
     > Set-ExecutionPolicy RemoteSigned
  
  2. Unblock the file in its Properties window (see yellow part in screenshot
     https://www.michaelcrump.net/files/image_634714178061387861.png)

Pace e salute.
Thibibi
