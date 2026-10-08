package deception

import (
	"fmt"
	"strings"
	"time"
)

// FakeFileSystem simulates a deceptive virtual file system designed to waste attacker time.
type FakeFileSystem struct {
	CurrentPath string
	Depth       int
}

// NewFakeFileSystem creates a stateful virtual filesystem tracker.
func NewFakeFileSystem() *FakeFileSystem {
	return &FakeFileSystem{
		CurrentPath: "/root",
		Depth:       0,
	}
}

// HandleCD changes directories, creating endless deceptive labyrinth traps.
func (fs *FakeFileSystem) HandleCD(target string) string {
	target = strings.TrimSpace(target)
	if target == "" || target == "~" {
		fs.CurrentPath = "/root"
		return ""
	}

	if target == ".." {
		if fs.Depth > 0 {
			fs.Depth--
		}
		if fs.CurrentPath == "/root" {
			fs.CurrentPath = "/"
		} else if fs.CurrentPath != "/" {
			fs.CurrentPath = "/root"
		}
		return ""
	}

	if strings.Contains(target, "secret") || strings.Contains(target, "vault") ||
		strings.Contains(target, "keys") || strings.Contains(target, "data") ||
		strings.Contains(target, "backup") || strings.Contains(target, "deep") ||
		strings.Contains(target, "sector") {
		fs.Depth++
		fs.CurrentPath = fmt.Sprintf("%s/%s", fs.CurrentPath, target)
		if fs.Depth > 3 {
			// Labyrinth mind-game loop: after 3 nested levels, loop back or change path subtly
			fs.CurrentPath = fmt.Sprintf("/root/vault/sub_sector_%d/quarantine", fs.Depth)
		}
		return ""
	}

	if target == "/etc" || target == "etc" {
		fs.CurrentPath = "/etc"
		return ""
	}
	if target == "/var/log" || target == "var/log" {
		fs.CurrentPath = "/var/log"
		return ""
	}

	fs.CurrentPath = fmt.Sprintf("%s/%s", fs.CurrentPath, target)
	return ""
}

// ListDirectory returns deceptive listings tailored to the current path.
func (fs *FakeFileSystem) ListDirectory() string {
	switch {
	case strings.Contains(fs.CurrentPath, "vault") || strings.Contains(fs.CurrentPath, "quarantine"):
		return "total 32\r\n" +
			"drwxr-x--- 3 root root 4096 Oct  8 20:14 .\r\n" +
			"drwxr-xr-x 8 root root 4096 Oct  8 20:12 ..\r\n" +
			"-rw------- 1 root root  829 Oct  8 20:15 target_telemetry_dump.enc\r\n" +
			"-r-------- 1 root root 1024 Oct  8 20:16 access_credentials.txt\r\n" +
			"drwx------ 2 root root 4096 Oct  8 20:18 deep_storage\r\n"
	case fs.CurrentPath == "/etc":
		return "total 72\r\n" +
			"drwxr-xr-x  8 root root 4096 Oct  8 18:01 .\r\n" +
			"drwxr-xr-x 19 root root 4096 Oct  8 18:00 ..\r\n" +
			"-rw-r--r--  1 root root 1842 Oct  8 18:01 passwd\r\n" +
			"-rw-r-----  1 root shadow 948 Oct  8 18:01 shadow\r\n" +
			"-rw-r--r--  1 root root  432 Oct  8 18:01 hosts\r\n" +
			"-rw-r--r--  1 root root  112 Oct  8 18:01 resolv.conf\r\n" +
			"drwxr-xr-x  2 root root 4096 Oct  8 18:01 security\r\n"
	case fs.CurrentPath == "/var/log":
		return "total 128\r\n" +
			"drwxr-xr-x  4 root root 4096 Oct  8 19:40 .\r\n" +
			"drwxr-xr-x 12 root root 4096 Oct  8 19:30 ..\r\n" +
			"-rw-r-----  1 syslog adm 34912 Oct  8 20:45 auth.log\r\n" +
			"-rw-r-----  1 syslog adm 81920 Oct  8 20:45 syslog\r\n" +
			"-rw-------  1 root   root 12480 Oct  8 20:45 intruder_trace.pcap\r\n"
	default: // /root
		return "total 48\r\n" +
			"drwx------ 5 root root 4096 Oct  8 20:10 .\r\n" +
			"drwxr-xr-x 3 root root 4096 Oct  8 18:00 ..\r\n" +
			"-rw------- 1 root root  220 Oct  8 18:02 .bash_history\r\n" +
			"drwx------ 2 root root 4096 Oct  8 18:05 .ssh\r\n" +
			"-r-------- 1 root root 1820 Oct  8 19:12 database_production.conf\r\n" +
			"-rw------- 1 root root  348 Oct  8 20:00 emergency_access.txt\r\n" +
			"drwxr-x--- 3 root root 4096 Oct  8 20:14 secrets_vault\r\n"
	}
}

// ReadFile generates deceptive honeytoken contents for high-interest files.
func (fs *FakeFileSystem) ReadFile(filename string, remoteIP string) string {
	filename = strings.ToLower(strings.TrimSpace(filename))

	if strings.Contains(filename, "id_rsa") {
		return "-----BEGIN OPENSSH PRIVATE KEY-----\r\n" +
			"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\r\n" +
			"NhAAAAAwEAAQAAAYEA3k79Pq09kQ7zL...[EVIDENCE TRAP BUFFER EXPANDED]...\r\n" +
			"=== WARNING: ACTIVE FORENSIC HONEYTOKEN ACCESSED FROM " + remoteIP + " ===\r\n" +
			"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\r\n" +
			"-----END OPENSSH PRIVATE KEY-----\r\n"
	}

	if strings.Contains(filename, "passwd") {
		return "root:x:0:0:root:/root:/bin/bash\r\n" +
			"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\r\n" +
			"bin:x:2:2:bin:/bin:/usr/sbin/nologin\r\n" +
			"sys:x:3:3:sys:/dev:/usr/sbin/nologin\r\n" +
			"sync:x:4:65534:sync:/bin:/bin/sync\r\n" +
			"sshd:x:107:65534::/run/sshd:/usr/sbin/nologin\r\n" +
			"syslog:x:108:113::/home/syslog:/usr/sbin/nologin\r\n" +
			"audit_sink:x:998:998:Forensic Recorder:/var/log/audit:/usr/sbin/nologin\r\n" +
			"net_mon:x:999:999:Packet Tarpit Supervisor:/var/run/trap:/bin/false\r\n"
	}

	if strings.Contains(filename, "shadow") {
		return "root:$6$v7kX0fR9$G8bW3V8lD9s3w.H7gE8qV0bA.9uC2oP4rE.4qL9yD8s3w.H7gE8qV0bA:19638:0:99999:7:::\r\n" +
			"daemon:*:19638:0:99999:7:::\r\n" +
			"audit_sink:!:19638:0:99999:7:::\r\n"
	}

	if strings.Contains(filename, "emergency") || strings.Contains(filename, "access") {
		return "=== EMERGENCY ACCESS TOKEN LIST ===\r\n" +
			"Master DB Node: 10.0.14.88:5432\r\n" +
			"Auth Token    : SEC-PROD-9812-4410-X\r\n" +
			"Alert Status  : SILENT TRIPWIRE ACTIVE FOR REMOTE IP " + remoteIP + "\r\n"
	}

	if strings.Contains(filename, "database") || strings.Contains(filename, "conf") {
		return "# Production Database Configuration\r\n" +
			"DB_HOST=127.0.0.1\r\n" +
			"DB_PORT=5432\r\n" +
			"DB_USER=cluster_admin\r\n" +
			"DB_PASS=S3cur3_K3y_Vault_9981!\r\n" +
			"DB_NAME=auth_credentials_store\r\n" +
			"# Notice: Connections mirrored to security forensic socket\r\n"
	}

	return fmt.Sprintf("cat: %s: Permission denied (File locked by kernel audit policy)\r\n", filename)
}

// GetProcessList returns a realistic process tree spiked with surveillance threads.
func GetProcessList() string {
	return "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n" +
		"root           1  0.0  0.2 168244 11200 ?        Ss   18:00   0:02 /sbin/init\r\n" +
		"root           2  0.0  0.0      0     0 ?        S    18:00   0:00 [kthreadd]\r\n" +
		"root           3  0.0  0.0      0     0 ?        I<   18:00   0:00 [rcu_gp]\r\n" +
		"root         412  0.0  0.1  28412  4820 ?        Ss   18:01   0:00 /lib/systemd/systemd-journald\r\n" +
		"root         440  0.0  0.1  21588  4100 ?        Ss   18:01   0:00 /usr/sbin/cron -f\r\n" +
		"syslog       451  0.0  0.1 223400  4900 ?        Ssl  18:01   0:01 /usr/sbin/rsyslogd -n -iNONE\r\n" +
		"root         680  0.1  0.3  15940  7200 ?        Ss   18:02   0:05 /usr/sbin/sshd -D\r\n" +
		"root         899  0.2  0.4  84520 12800 ?        S<sl 18:05   0:14 /usr/lib/security/kforensicd --live-sink\r\n" +
		"root         902  0.1  0.2  42100  6400 ?        S    18:05   0:08 [trap_supervisor]\r\n" +
		"root        1420  0.0  0.2  14800  5120 pts/0    Ss   20:48   0:00 -bash\r\n" +
		"root        1501  0.0  0.1  11420  3200 pts/0    R+   20:50   0:00 ps aux\r\n"
}

// GetSystemHistory returns a fake command history that unsettles the attacker.
func GetSystemHistory() string {
	return "  488  cd /etc/network && ip route show\r\n" +
		"  489  systemctl status sshd\r\n" +
		"  490  tail -f /var/log/auth.log\r\n" +
		"  491  iptables -L -n -v\r\n" +
		"  492  auditctl -a always,exit -F arch=b64 -S execve -k intrusion_trap\r\n" +
		"  493  modprobe forensic_tap live=1\r\n" +
		"  494  echo 'Active trap monitor initialized' >> /var/log/audit.log\r\n" +
		"  495  history -w\r\n"
}

// GetUnameOutput returns standard simulated Linux kernel details.
func GetUnameOutput(fakeHostname, fakeOS string) string {
	return fmt.Sprintf("Linux %s 5.15.0-89-generic #99-Ubuntu SMP %s x86_64 GNU/Linux\r\n", fakeHostname, time.Now().Format("Mon Jan 02 15:04:05 MST 2006"))
}
