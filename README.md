# Build a hardened system with NixOS

## Introduction

In today's digital age, protecting our computers and the information they hold is more important than ever. The motivations behind cyber attacks are as diverse as the individuals and groups who perpetrate them. Here are some of the most common reasons:

 - **Data breaches:** Hackers can steal sensitive information like passwords, financial data, or personal records, which can have devastating consequences.

 - **Identity theft:** Criminals can use stolen information to impersonate you, open fraudulent accounts, and ruin your credit.

 - **Ransomware attacks:** Malicious actors can encrypt your data and demand payment to unlock it, leaving you powerless without proper backups.

 - **System disruptions:** Viruses and malware can damage your computer, crash systems, and disrupt critical operations.

 - **Financial losses:** Data breaches, downtime, and cybercrime can cost businesses millions of dollars annually.

Cybersecurity experts develop defense mechanisms to counter known attacks, yet attackers continually devise new types of assaults. Therefore, computer security is not a one-time solution but an ongoing process.

### System Hardening

A hardened system is one that has been configured to be more resistant to cyberattacks and security breaches compared to a standard system. This increased resistance is achieved through a variety of techniques and measures, which can be broadly categorized into three main areas:

**1. Reducing the Attack Surface:**

This involves removing or disabling unnecessary features, services, and applications that attackers could potentially exploit. Examples include:
- Removing unused accounts and privileges.
- Disabling services not required for the system's core functionality.
- Patching vulnerabilities in software promptly.
- Following secure coding practices to minimize software vulnerabilities.

**2. Strengthening Defense Mechanisms:**

This involves setting up and configuring defensive security controls to detect and prevent attacks. Examples include:
- Implementing strong authentication and authorization controls.
- Installing and configuring intrusion detection and prevention systems (IDS/IPS).
- Using antivirus and anti-malware software.
- Implementing data encryption for sensitive information.
- Configuring firewalls and network segmentation to restrict access to critical systems.

**3. Enforcing Security Policies and Procedures:**

This involves establishing and enforcing security policies and procedures to ensure users and administrators follow best practices. Examples include:
- Providing security awareness training for users.
- Implementing logging and auditing to monitor system activity for suspicious behavior.
- Having a plan for incident response and disaster recovery.

Overall, the goal of system hardening is to make it as difficult and time-consuming as possible for attackers to gain access to the system and its data. By implementing the various techniques mentioned above.

Here are some additional points to consider:

- The level of hardening required varies depending on the system's purpose and sensitivity of the data it stores. Critical systems often require more stringent hardening measures than less sensitive ones.
- Hardening is an ongoing process, not a one-time event. New vulnerabilities are discovered regularly, and attackers are constantly developing new techniques. Therefore, it's crucial to regularly review and update hardening measures to stay ahead of the threats.

### Why NixOS?

NixOS offers distinct advantages in system hardening due to its unique approach to package management and system configuration. One key strength lies in its declarative and reproducible nature, where the entire system configuration is specified in a single configuration file. This not only simplifies administration but also enhances security by minimizing the risk of configuration drift.

The functional package manager, Nix, employed by NixOS, ensures that packages are isolated and have well-defined dependencies, reducing the likelihood of vulnerabilities arising from conflicting library versions. The ability to create isolated environments using Nix enables the testing and deployment of applications in a controlled manner, contributing to overall system robustness.

Furthermore, NixOS supports atomic upgrades and rollbacks, allowing for seamless transitions between system configurations. This not only facilitates quick recovery from potential issues but also promotes a more resilient and secure system by ensuring that updates can be easily reverted.

# Guidelines for System Hardening

One should consider the following guidelines when implementing system hardening measures:

## 1. Authentication

Authentication plays a crucial role in safeguarding any system from potential threats. Before granting access to resources or data, it is essential to verify a user's identity to ensure authorized use of the system. Inadequate authentication measures can lead to severe consequences such as data breaches and security incidents. 

For an effectively hardened system, it is advisable to adopt a role-based authentication approach. This entails classifying users based on their roles and providing access to only the necessary information required for their tasks. By limiting access to specific areas, you can minimize the system's attack surface and decrease potential vulnerabilities.

To strengthen the authentication process, there are several best practices to follow, such as strong password policy, forcing privileged users to use multi-factor authentication, and using SSH keys for remote access. Additionally, implementing temporary account suspension after multiple failed login attempts can prevent unauthorized access.

### 1.1 Enforce Strong Password
To enforce strong passwords in NixOS, one can use the pam_pwquality.so module. This module provides a way to enforce password complexity requirements such as minimum length, complexity, and history.

Here is an example of how to configure pam_pwquality.so in NixOS:

~~~ Nix
security.pam.services.passwd.rules.password.pwquality = {
  control = "required"; 
  modulePath = "${pkgs.libpwquality.lib}/lib/security/pam_pwquality.so"; 
  # order BEFORE pam_unix.so
  order =  config.security.pam.services.passwd.rules.password.unix.order - 10;
  settings = {
    retry = 3;
    #local_users_only = true;
    minlen = 8;
    difok = 6;
    dcredit = -1;
    ucredit = 1;
    ocredit = -1;
    lcredit = 1;
    enforce_for_root = true;
  }; 
};
~~~

This configuration enforces the following password requirements:

- Minimum length of 12 characters
- At least 6 characters must be different from the previous password
- At least one digit, one uppercase letter, and one lowercase letter
- At least one special character
- Passwords cannot contain the user’s name or username
You can modify these settings to suit your needs.

**Note:** This feature is unstable. 
https://github.com/NixOS/nixpkgs/issues/287420

### 1.2 Enable Multifactor Authentication (MFA)
NixOS provides following methods for MFA:
- **YubiKey:** Physical hardware token for secure authentication.
- **Time-based One-Time Passwords (TOTP):** Apps like Google Authenticator generate rotating codes.
To enable MFA, configure necessary PAM module.

**For YubiKey:**
```Nix
security.pam.yubico.enable = true;
security.pam.yubico.control = "required";  # Enforce MFA for all logins
```

**For TOTP:**
```Nix
security.pam.google-authenticator.enable = true;
security.pam.google-authenticator.control = "required"; # Enforce MFA for all logins
```

## 2. Remote Access
To strengthen system security, consider restricting or disabling remote access mechanisms. Here are some recommendations:

- **Prioritize Disabling Remote Login:** Aim to eliminate remote login whenever possible. This completely removes an attack vector and simplifies security management.

- **Use Strong Authentication for Remaining Access:** If remote login cannot be disabled, replace password authentication with key-based access using SSH keys. SSH keys offer significantly enhanced security compared to passwords, rendering brute-force attacks impractical.

- **Elevate User Privileges Only When Necessary:** Avoid granting remote access with root privileges. Instead, assign users the minimum access level required for their tasks. This principle of least privilege minimizes potential damage caused by compromised credentials.

In NixOS following configuration can be used to controll remote access:

```Nix
services.openssh = {
  enable = true;
  # require public key authentication for better security
  settings.PasswordAuthentication = false;
  # keyboard-interactive authentication is disallowed.
  settings.KbdInteractiveAuthentication = false;
  # disable root login
  settings.PermitRootLogin = "no";
};
```
Use following configuration to setup ssh keys:

We can also store the public keys in /etc/nixos/configuration.nix:

```Nix
users.users."user".openssh.authorizedKeys.keys = [
  "ssh-rsa AAAAB3Nz....6OWM= user" # content of authorized_keys file
];
```
or use a custom path for the authorized_keys file:

```Nix
users.users."user".openssh.authorizedKeys.keyFiles = [
  /etc/nixos/ssh/authorized_keys
];
```

## 3. Remove Unnecessary Software

While the addition of new software may appear enticing, it's crucial to recognize that not all packages are essential for your system's functionality. The more packages, software, libraries, and third-party repositories you incorporate, the larger the attack surface becomes, increasing the potential for security vulnerabilities. 

NixOS offers a minimal profile for constructing NixOS images, although it does not achieve absolute minimalism. It is advisable to prune unnecessary packages from the Nix store. The Nix garbage collector is a valuable tool that can identify and eliminate packages that are not in active use. Shared libraries often come bundled in a package, with many of them potentially unnecessary for the application. It is recommended to discern and remove such redundant libraries.

Here is an example of a NixOS configuration that serves as a starting point for a minimal system.

```Nix
{
  imports = [
    <nixpkgs/nixos/modules/profiles/headless.nix>  # For Headless system
    <nixpkgs/nixos/modules/profiles/minimal.nix>   # Minimal NixOS profile
  ];

  # only add strictly necessary modules
  boot.kernelModules = [];
  boot.initrd.includeDefaultModules = false;
  boot.initrd.kernelModules = [];  # Add necessary kernel modules here
  disabledModules =
    [ <nixpkgs/nixos/modules/profiles/all-hardware.nix>
      <nixpkgs/nixos/modules/profiles/base.nix>
    ];

  # disable useless software
  environment.defaultPackages = [];  # Add necessary packages here
  xdg.icons.enable  = false;
  xdg.mime.enable   = false;
  xdg.sounds.enable = false;
}
```
## 4. Restrict Network Access
Network access restriction involved controlling access of data to and from network to enhance security. Firewalls are a fundamental tool for restricting network traffic. They can be implemented at the network perimeter, between network segments, or on individual devices. Firewalls enforce access control policies based on rules, allowing or denying traffic based on factors like source IP, destination IP, port numbers, and protocols.

NixOS provides an interface to configure the firewall through the option `networking.firewall`.

The default firewall uses iptables. To use the newer nftables instead, additionally set 'networking.nftables.enable = true;'
To explicitly enable it add the following into your NixOS configuration: 

```Nix
networking.firewall.enable = true;
```
To allow specific TCP/UDP ports or port ranges on all interfaces, use following syntax: 

```Nix
networking.firewall = {
  enable = true;
  allowedTCPPorts = [ 80 43 ];
  allowedUDPPortRanges = [
    { from = 4000; to = 4001; }
    { from = 8000; to = 8002; }
  ];
};
```

Interface-specific firewall rules can be applied like this:

```Nix
networking.firewall.interfaces."eth0".allowedTCPPorts = [ 80 443 ];
```

In NixOS many services also provide an option to open the required firewall ports automatically. For example, the media server Jellyfin offers the option 

```Nix
services.jellyfin.openFirewall = true;
```

which will open the required TCP ports.

Firewall rules may be over written by docker containers too. So one should use these configurations carefully.  

You can craft IPTables rules to permit or deny packets to/from specific IP addresses. For NixOS Firewall options, refer to the link provided below:

[NixOS Firewall Options](https://mynixos.com/nixpkgs/options/networking.firewall)

## 5. Restrict access of USB interface

Depending on the criticality of your system, there are instances where it becomes necessary to restrict the usage of USB sticks on a Linux host. There are several methods to prevent the use of USB storage, and a simple one is as follows:
You can configure USB interface from kernel configuration based on the requirement:
- To disable USB interface set 'CONFIG_USB_SUPPORT=n' 
- To disable only USB network adapter set 'CONFIG_USB_NET_DRIVERS=n'
- To disable only USB mass storage set 'CONFIG_USB_STORAGE=n'
- To disable only USB serial port set 'CONFIG_USB_SERIAL=n'

For each type of USB device, a corresponding configuration is available, and it can be disabled in the kernel configuration.

To override the kernel configuration in NixOS, you can utilize the `boot.kernelPatches` attribute. An example for disabling USB mass storage is provided below:
```Nix
boot.kernelPatches = [
    {
      name = "disable-usb-storage-config";
      patch = null;
      extraConfig = ''
        USB_NET_DRIVERS n
      '';
    }
  ];
```

## 6. Use Hardened Linux Kernel
NixOS offers a fortified Linux kernel based on recommendations from the community. It can be utilized through the following options:

```Nix
boot.kernelPackages = mkDefault pkgs.linuxPackages_hardened;
```
One can craft a customized hardened kernel tailored to specific requirements. 

[Hardened Kernel Config Recommendation](http://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project/Recommended_Settings)

[NixOS Hardened Kernel Config](https://github.com/NixOS/nixpkgs/blob/nixos-23.11/pkgs/os-specific/linux/kernel/hardened/config.nix)

## 7. Enhance Security with AppArmor
Linux is a secure operating system that comes equipped with various built-in security subsystems by default to ensure the safety of your device. Two notable subsystems, namely SELinux (Security Enhanced Linux) and AppArmor, have been developed as Linux security module to offer enhanced security features.

NixOS employs a unique approach to package management and system configuration using the Nix language. Its focus is on immutability and reproducibility. 

SELinux assigns a security label to every file and process on the system. It stores security labels as extended attributes (xattrs) within the filesystem itself. Modifying files in the Nix store after they have been built to assign security labels etc. violates immutability. Supporting SELinux would require significant changes to the core principles of how NixOS manages its configurations and packages. However on the otherhand [AppArmor](https://gitlab.com/apparmor/apparmor/-/wikis/Documentation) is more compatible with Nix because it doesn't require attaching metadata to files. [AppArmor](https://gitlab.com/apparmor/apparmor/-/wikis/Documentation) security can be enabled in NixOS using following configuration options.

```Nix
security.apparmor.enable = true;
security.apparmor.policies."application".profile = ''
      include "${profile-path-here}"
    '';
security.apparmor.includes."local/bin.transmission-daemon" = ''
      # Rules
    '';
```
More configuration options are available in AppArmor. For NixOS Firewall options, refer to the link provided below:

[AppArmor config options](https://mynixos.com/nixpkgs/options/security.apparmor)

Example setting:

```Nix
    security.apparmor.enable = true;
    security.apparmor.policies."bin.transmission-daemon".profile = ''
      include "${cfg.package.apparmor}/bin.transmission-daemon"
    '';
    security.apparmor.includes."local/bin.transmission-daemon" = ''
      r ${config.systemd.services.transmission.environment.CURL_CA_BUNDLE},

      owner rw ${cfg.home}/${settingsDir}/**,
      rw ${cfg.settings.download-dir}/**,
      ${optionalString cfg.settings.incomplete-dir-enabled ''
        rw ${cfg.settings.incomplete-dir}/**,
      ''}
      ${optionalString cfg.settings.watch-dir-enabled ''
        r${optionalString cfg.settings.trash-original-torrent-files "w"} ${cfg.settings.watch-dir}/**,
      ''}
      profile dirs {
        rw ${cfg.settings.download-dir}/**,
        ${optionalString cfg.settings.incomplete-dir-enabled ''
          rw ${cfg.settings.incomplete-dir}/**,
        ''}
        ${optionalString cfg.settings.watch-dir-enabled ''
          r${optionalString cfg.settings.trash-original-torrent-files "w"} ${cfg.settings.watch-dir}/**,
        ''}
      }

      ${optionalString (cfg.settings.script-torrent-done-enabled &&
                        cfg.settings.script-torrent-done-filename != null) ''
        # Stack transmission_directories profile on top of
        # any existing profile for script-torrent-done-filename
        # FIXME: to be tested as I'm not sure it works well with NoNewPrivileges=
        # https://gitlab.com/apparmor/apparmor/-/wikis/AppArmorStacking#seccomp-and-no_new_privs
        px ${cfg.settings.script-torrent-done-filename} -> &@{dirs},
      ''}
    '';
```

[Profiles](https://gitlab.com/morfikov/apparmemall)


## 8. Sandbox Application:
A sandbox enables you to execute a program within an isolated environment, with either restricted or no access to the rest of your system. This can be employed to enhance the security of applications or execute untrusted programs.
[Firejail](https://wiki.archlinux.org/title/firejail) is a SUID sandbox program that reduces the risk of security breaches by restricting the running environment of untrusted applications using Linux namespaces, seccomp-bpf and Linux capabilities. It allows a process and all its descendants to have their own private view of the globally shared kernel resources, such as the network stack, process table, mount table. Firejail can work in AppArmor environment too, and it is integrated with Linux Control Groups.

Use following options to enable Firejail globally 

```Nix
programs.firejail.enable = true;
```

**Usage:**

To start an application in a sandboxed enviroment use Firejail like this

```
firejail bash
```

For a graphical application like Firefox web browser, it is recommended to also use a profile

```
firejail --profile=$(nix --extra-experimental-features nix-command --extra-experimental-features flakes eval -f '<nixpkgs>' --raw 'firejail')/etc/firejail/firefox.profile firefox
```

**Configuration:**

You can also use the Firejail NixOS module for a persistent usage of specific applications which should always run in Firejail. The following example wraps the browser Librewolf and the messenger Signal in a Firejail environment. The usual program path to librewolf and signal-desktop will be overwritten by the Firejail-wrapper.

```Nix
programs.firejail = {
  enable = true;
  wrappedBinaries = {
    librewolf = {
      executable = "${pkgs.librewolf}/bin/librewolf";
      profile = "${pkgs.firejail}/etc/firejail/librewolf.profile";
      extraArgs = [
        # Required for U2F USB stick
        "--ignore=private-dev"
        # Enforce dark mode
        "--env=GTK_THEME=Adwaita:dark"
        # Enable system notifications
        "--dbus-user.talk=org.freedesktop.Notifications"
      ];
    };
    signal-desktop = {
      executable = "${pkgs.signal-desktop}/bin/signal-desktop --enable-features=UseOzonePlatform --ozone-platform=wayland";
      profile = "${pkgs.firejail}/etc/firejail/signal-desktop.profile";
      extraArgs = [ "--env=GTK_THEME=Adwaita:dark" ];
    };
  };
};
```

## 9. Detect Viruses:
Antivirus software plays a crucial role in computer security by serving as a proactive defense against malicious software, commonly known as malware.
NixOS has inbuilt support for opensource ClamAV antivirus. ClamAV is an open source (GPLv2) anti-virus toolkit developed by Cisco, designed especially for e-mail scanning on mail gateways. It provides a number of utilities including a flexible and scalable multi-threaded daemon, a command line scanner and advanced tool for automatic database updates. The core of the package is an anti-virus engine available in a form of shared library. It can be enabled using below given config options

```
services.clamav.daemon.enable = true;
services.clamav.updater.enable = true;  # Enable ClamAV freshclam updater.
```
It can be configuraed using options given in the link.

[ClamAV configs](https://mynixos.com/search?q=clamav)

## 10. Sysctl Configuration for Security:
Sysctl can be used to adjust kernel settings to make it harder for attacks and improve security. Following settings are recommneded to enhance security:

### 10.1 System Security
#### 10.1.1 Restrict ptrace
One process can inspect and manipulate internal state of another process using ptrace system call. ptrace is used by debugger, strace, and other code coverage analysis tools. Attackers can exploit this to change status of other running processes. Following configuration restricts usage of ptrace to only processes with the CAP_SYS_PTRACE capability. Alternatively, set this to 3 to disable ptrace entirely.
```Nix  
  boot.kernel.sysctl."kernel.yama.ptrace_scope" = mkForce 2;
```

#### 10.1.2 Hide Kernel Pointers
Kernel pointer are not hidded by default, it can be uncovered by reading contents of `/proc/kallsyms`. Kernel pointers are very usefull to exploit kernel. This setting completely hides pointers(sets to 0) regardless of the previledge of the accessing process. Alternatively, you can set `kernel.kptr_restrict=1` to only hide kernel pointers from processes without the CAP_SYSLOG capability. 

```Nix
  boot.kernel.sysctl."kernel.kptr_restrict" = mkForce 2;
```
#### 10.1.3 Disable bpf JIT compiler
JIT spraying is an attack where the behavior of a Just-In-Time compiler is (ab)used to load an attacker-provided payload into an executable memory area of the operating system [3]. This is usually achieved by passing the payload instructions encoded as constants to the JIT compiler and then using a suitable OS bug to redirect execution into the payload code

```Nix
  boot.kernel.sysctl."net.core.bpf_jit_enable" = mkDefault false;
```
eBPF exposes large attack surface. If eBPF JIT is need of the system then it must be restricted using following options.

```Nix
  boot.kernel.sysctl."kernel.unprivileged_bpf_disabled" = mkOverride 500 1;
  boot.kernel.sysctl."net.core.bpf_jit_harden" = mkForce 2;
```

#### 10.1.4 Disable ftrace debugging
Ftrace is an internal tracer designed to help out developers and designers of systems to find what is going on inside the kernel. It can be used for debugging or analyzing latencies and performance issues. Attackers can use these traces to gather sensitive information about the system to plan an attack.
```Nix
  boot.kernel.sysctl."kernel.ftrace_enabled" = mkDefault false;
```

#### 10.1.5 Enable kernel address space randomization
Address space randomization increases the difficulty of performing a buffer overflow attack that requires the attacker to know the location of an executable in memory.

```Nix
  boot.kernel.sysctl."kernel.randomize_va_space" = mkForce 2;
```
#### 10.1.6 Restrict core dump
When a program experiences a core dump, it creates a file containing a snapshot of its memory at the time of the crash. This file, known as a core dump file, aids developers in diagnosing and fixing the underlying issues leading to the program's failure.
However, it's crucial to recognize that in certain scenarios, core dump files can pose a security risk. Attackers may leverage these files to gain insights into the program's memory layout, potentially revealing vulnerabilities that could be exploited for unauthorized access or other malicious purposes. Therefore, managing and securing core dump files is an essential aspect of overall system security. 

```Nix
  boot.kernel.sysctl."fs.suid_dumpable" = mkOverride 500 0;
```

#### 10.1.7 Restrict kernel log
The kernel log contains valuable information about the kernel, offering insights that attackers could leverage to strategize for an attack. It is advisable to limit the kernel log's accessibility to prevent the disclosure of critical kernel details, thereby enhancing the overall security.
Despite the dmesg restriction, the kernel log will still be displayed in the console during boot. This information can also be usefull for attacker. It is better to expose minimum information during boot. One can set kernel log level between 0 to 3 to display minimum required information in kernel log. It is recommended to set low console log level in boot params. 

```Nix
  boot.kernel.sysctl."kernel.dmesg_restrict" = mkForce 1;
  boot.consoleLogLevel = mkOverride 500 3;
```

Linux kernel defines following log levels:

Log Level | kernel flag  | Description 
----------|--------------|------------
0 	       | KERN_EMERG 	 | An emergency condition; the system is probably dead
1 	       | KERN_ALERT 	 | A problem that requires immediate attention
2 	       | KERN_CRIT 	  | A critical condition
3 	       | KERN_ERR 	   | An error
4 	       | KERN_WARNING | A warning
5 	       | KERN_NOTICE 	| A normal, but perhaps noteworthy, condition
6 	       | KERN_INFO 	  | An informational message
7 	       | KERN_DEBUG 	 | A debug message, typically superfluous 

#### 10.1.8 Restrict userfaultfd() system call
userfaultfd() system call is a Linux kernel feature that provides a mechanism for handling user-space page faults. It allows applications to be notified when a page fault occurs and gives them the opportunity to handle the fault in user space rather than relying on the kernel to handle it. userfaultfd() system call can be combined with use-after-free vulnerabilities to perform an attack. It is recommended to restrict usage of this system call. 

```Nix
  boot.kernel.sysctl."vm.unprivileged_userfaultfd" = mkForce 0;
```

#### 10.1.9 Disable kexec() system call
The kexec system call is allows a user-space process to load and execute a new kernel from within an already running kernel, without the need to reboot the system. This can be useful for tasks such as kernel debugging, testing, or updating the kernel without a full system restart. This can be abused to load a malicious kernel. It is recommended to disable this system call.

```Nix
  boot.kernel.sysctl."kernel.kexec_load_disabled" = mkForce 1;
```
or 

```Nix
  security.protectKernelImage = mkDefault true;
```

#### 10.1.9 Restrict/Disable SysRq
The SysRq key on a computer keyboard has some powerful but risky debugging features that regular users can access. This is not just a concern for situations where someone has physical access to the computer; it can also be a problem if someone tries to use it remotely. By adjusting a setting called sysctl, you can limit a user's ability to use the SysRq key to only perform a secure action key, which is essential for securely accessing the root (administrator) account. Alternatively, you can set the sysctl value to 0 to completely turn off the SysRq key functionality.

```Nix
  boot.kernel.sysctl."kernel.kexec_load_disabled" = mkForce 1;
```

Here is the list of possible values:

Value | Description
------|------
0     | Disable sysrq completely
1     | Enable all functions of sysrq
2     | Enable control of console logging level
4     | Enable control of keyboard (SAK, unraw)
8     | Enable debugging dumps of processes etc.
16    | Enable sync command
32    | Enable remount read-only
64    | Enable signalling of processes (term, kill, oom-kill)
128   | Allow reboot/poweroff
256   | Allow nicing of all RT tasks

#### 10.1.10 Disable user namespace cloning for unprivileged users
User namespaces allow unprivileged users to create isolated environments with their own UID and GID mappings, namespaces, and capabilities. This is useful for creating containers and other forms of process isolation.
This can make vulnerabilities in the Linux kernel much more easily exploitable. If you don't need, disable it.

```Nix
  boot.kernel.sysctl."kernel.unprivileged_userns_clone" = mkForce 0;
```
or

```Nix
  security.unprivilegedUsernsClone = mkDefault false;
```

## 10.1.11 Disable dynamic kernel modules
Allowing the dynamic loading of kernel modules provides a potential attack vector for unauthorized users or malicious software to introduce arbitrary code into the kernel. Disabling module loading helps prevent the introduction of unauthorized or malicious kernel modules.

```Nix
  boot.kernel.sysctl."kernel.modules_disabled" = mkForce 1;
```
or

```Nix
  security.lockKernelModules = mkDefault true;
```


### 10.2 Network Security

#### 10.2.1 Disable IPv6
If you're not using IPv6 or the [dual stack](## "Coexistence of both IPv4 and IPv6 on the same network infrastructure."), it's a good idea to turn off IPv6. It will reduce the attack surface.

```Nix
  boot.kernel.sysctl."net.ipv6.conf.all.disable_ipv6" = mkForce 1;
  boot.kernel.sysctl."net.ipv6.conf.default.disable_ipv6" = mkForce 1;
  boot.kernel.sysctl."net.ipv6.conf.lo.disable_ipv6" = mkForce 1;
```

#### 10.2.2 Prevent SYN Flooding
When a device initiates a TCP connection, it sends a [SYN](## "Synchronize") packet to the server. The server, in response, sends a [SYN-ACK](## "synchronize-acknowledge") packet and awaits an [ACK](## "acknowledge") packet from the client to complete the connection. In a SYN flood attack, an attacker sends a large number of SYN packets without intending to complete the connections. This can overwhelm the server's resources and lead to a [DoS](## "Denial of Service") attack.
SYN cookies designed to help protect against such DoS attacks. Follwing settings are recommended to enable SYN cookies:

```Nix
  boot.kernel.sysctl."net.ipv4.tcp_syncookies" = mkForce 1;
  boot.kernel.sysctl."net.ipv4.tcp_syn_retries" = mkForce 2;
  boot.kernel.sysctl."net.ipv4.tcp_synack_retries" = mkForce 2;
  boot.kernel.sysctl."net.ipv4.tcp_max_syn_backlog" = mkForce 4096;
```

#### 10.2.3 Enable protection against time-wait assasination
In networking, when a TCP connection is closed, it enters the TIME-WAIT state for a certain period. This period is designed to ensure that any delayed or out-of-order packets related to the closed connection are handled properly. RFC 1337 identifies potential security risks during this TIME-WAIT period, specifically related to the reuse of the same tuple of IP addresses and port numbers.
Based on the recommendations outlined in RFC 1337, enable follwing setting to protect against time-wait assassination by dropping [RST packets](## "The Reset packet is employed to terminate an established TCP connection abruptly or to indicate an error condition.") for sockets in the time-wait state.

```Nix
  boot.kernel.sysctl."net.ipv4.tcp_rfc1337" = mkForce 1;
```
#### 10.2.4 Protection against IP Spoofing
IP spoofing is a technique where an attacker sends IP packets from a false (or "spoofed") source address in order to deceive the recipient about the origin of the message. This technique is used to perform DoS or Man in the Middle attack. To prevent such attack, source validation is must for the packets received from all the interfaces. [RP-Filter](## "Reverse Path Filtering") helps prevent IP spoofing by checking the source address of incoming packets against the routing table to verify that the packet came from a legitimate source. Here is the setting you can use to enable RP filter.

```Nix
  boot.kernel.sysctl."net.ipv4.conf.all.rp_filter" = mkForce 1;
  boot.kernel.sysctl."net.ipv4.conf.default.rp_filter" = mkForce 1;
```
#### 10.2.5 Disable Redirect Acceptance
[ICMP](## "Internet Control Message Protocol") redirect messages are typically sent by routers to inform hosts that there is a more optimal route for a particular destination. When a host receives an ICMP Redirect message, it can update its routing table to use the suggested route. 
It's worth noting that while ICMP redirect messages can be useful for optimizing routing in some scenarios, they can also be misused to perform Man in the middle attack. These configurations disable ICMP redirect acceptance and sending:

```Nix
  boot.kernel.sysctl."net.ipv4.conf.all.accept_redirects" = mkForce 0;
  boot.kernel.sysctl."net.ipv4.conf.default.accept_redirects" = mkForce 0;
  boot.kernel.sysctl."net.ipv4.conf.all.secure_redirects" = mkForce 0;
  boot.kernel.sysctl."net.ipv4.conf.default.secure_redirects" = mkForce 0;
  boot.kernel.sysctl."net.ipv4.conf.all.send_redirects" = mkForce 0;
  boot.kernel.sysctl."net.ipv4.conf.default.send_redirects" = mkForce 0;
```

#### 10.2.6 Ignore source-routed IP packets
When source routing is enabled, the system accepts source-routed IP packets. In source routing, the sender of a packet can specify the route it should take through the network.
Source routing can be misused for various attacks, including IP spoofing and other forms of packet manipulation. Disabling acceptance of source-routed packets is generally a good security practice.

```Nix
  boot.kernel.sysctl."net.ipv4.conf.all.accept_source_route" = mkForce 0;
  boot.kernel.sysctl."net.ipv4.conf.default.accept_source_route" = mkForce 0;
```

#### 10.2.7 Ignore ICMP echo requests
ICMP Echo Requests are commonly associated with the "ping" command, which is used to test the reachability of a host on an Internet Protocol (IP) network. This parameter is often used as a security measure to reduce the visibility of a system to potential attackers. 

```Nix
  boot.kernel.sysctl."net.ipv4.icmp_echo_ignore_all" = mkForce 1;
```

#### 10.2.8 Log Martian packets
Martian packets are packets with source or destination addresses that are not routable or are reserved for special purposes. These packets are considered anomalous and may indicate a misconfiguration or potentially malicious activity. Kernel should log such packets to identify malicous activity.

```Nix
  boot.kernel.sysctl."net.ipv4.conf.all.log_martians" = mkDefault true;
  boot.kernel.sysctl."net.ipv4.conf.default.log_martians" = mkDefault true;
```
#### 10.2.9 Ignore bogus ICMP error responses
Bogus ICMP error responses could be generated by misconfigured or malicious devices and may not accurately reflect the state of the network. Ignoring these responses can be a security measure to prevent potential information leakage or exploitation

```Nix
  boot.kernel.sysctl."net.ipv4.icmp_ignore_bogus_error_responses" = mkForce 1;
```

## 11. NixOS options for enhanced security

### 11.1 Use Scudo memory allocator
Scudo is an open-source memory allocator designed for C and C++ programs. It is an alternative to other memory allocators like the default allocator in the C library (e.g. malloc and free) The primary goal of Scudo is to provide efficient memory allocation and deallocation while also focusing on security aspects. Scudo incorporates security features to mitigate memory-related vulnerabilities, such as buffer overflows or use-after-free errors. It includes mechanisms to detect and prevent certain types of memory corruption. Use following option to enable Scudo memory allocator:

```Nix
  environment.memoryAllocator.provider = mkDefault "scudo";
  environment.variables.SCUDO_OPTIONS = mkDefault "ZeroContents=1";
```

### 11.2 Disable Hyper-threading
Hyper-threading improves overall system performance by making better use of CPU resources, there are security considerations associated with it. It can introduce possibility of side-channel attacks. It can be disabled using following options:

```Nix
  security.allowSimultaneousMultithreading = mkDefault false;
```

### 11.3 Force page table isolation
[PTI](## "Page Table Isolation") is a security feature implemented in the Linux kernel to mitigate certain types of attacks, particularly those related to speculative execution vulnerabilities like Meltdown and Spectre. These vulnerabilities could potentially allow unauthorized access to sensitive data in the kernel memory.
PTI separates the page tables used for user-space and kernel-space, preventing user-space processes from directly accessing kernel memory. Each process has its own set of page tables for accessing user-space and a separate set for accessing kernel-space. When a process transitions between user-space and kernel-space, the kernel switches between the user-space page tables and the kernel-space page tables. This separation helps prevent the speculative execution of user-space instructions from leaking sensitive kernel data. PTI can have a performance impact because of the increased overhead associated with the switching of page tables.

```Nix
  security.forcePageTableIsolation = mkDefault true;
```
### 11.4 Flush L1 Data cache before entering guest vm
Flushing the L1 data cache before entering a guest virtual machine is a performance optimization and security measure to ensure that the guest VM starts with a clean and consistent state. This is particularly relevant in scenarios where a hypervisor or virtual machine monitor (VMM) is managing multiple virtual machines on a system.
Flushing the L1 data cache helps prevent potential information leakage or security vulnerabilities that could arise from remnants of data left in the cache from the host or other VMs.

```Nix
security.virtualisation.flushL1DataCache = mkDefault "always";
```

### 11.5 Adjust Kernel Params
In NixOS kernel boot params can be passed using following options:

```Nix
 boot.kernelParams = [
  "param1"
  "param2"
 ];
```
Here are some kernel parameters that can be used to strengthen security of a system.

### 11.5.1 Enable SLUB debugger
SLUB is responsible for the organization, allocation and freeing of objects from a [slab-cache](## "The slab cache is a memory management mechanism used in the Linux kernel to efficiently manage and allocate memory for kernel data structures."). It is a part of the Linux kernel's memory allocator, which handles dynamic memory allocation for various kernel objects. Memory-related vulnerabilities are common sources of security exploits. Bugs in the kernel's memory management, such as those related to SLUB or other allocators, could potentially lead to privilege escalation, information disclosure, or denial-of-service attacks. So it is important to enable SLUB debugger in order to identify and fix potential vulnerability.

```Nix
"slub_debug=FZPU"
```

This will enable following functionality in SLUB debugger:

Z : Provide [RED (guard) zones](## "To detect out of bound access RED zones are created on both sides of the object. These RED zones are filled with markers to indicate the allocation state of an object. The RED zones of the allocated objects are filled with the value 0xcc and the RED zones of the free objects are filled with the value 0xbb. An out of bound access can change these marker values.") around SLUB objects
    
P : [Poisoning (object and padding)](## "Page poisoning, in the context of operating systems and memory management, is a technique used to detect and identify memory corruption or use-after-free vulnerabilities. It involves marking or poisoning pages of memory when they are freed or released, making it evident if a program attempts to access or modify memory that has already been deallocated.")
    
F : Perform sanity checks on SLUB objects
    
U : User tracking (free and alloc)

#### 11.5.2 Scrub Memory
Filling freed pages and heap objects with zeroes is a security practice known as "zeroing memory" or "memory scrubbing." This practice involves overwriting the contents of memory areas, such as freed pages or deallocated heap objects, with zeros before making them available for reuse. It prevents information leakage, and can be enabled using following kernel params:

```Nix
"init_memory=0"
```

#### 11.5.3 Randomize page allocation
Page allocation randomization significantly improves the security of a system, specially against those attacks who exploit memory related vulnerability. Below is the param to enable this feature in kernel:

```Nix
"page_alloc.shuffle=1"
```

#### 11.5.4 Panic on uncorrectable memory access

```Nix
"mce=0"
```

Mostly useful for systems with ECC memory, if you set "mce" to 0, the kernel will panic if it detects any uncorrectable errors through the machine check exception system. The corrected errors will just be logged. The "mce=1" (default) will cause a SIGBUS signal for uncorrected errors. This means that malicious processes attempting to exploit hardware issues can keep trying repeatedly, facing only a SIGBUS signal when they fail. 

#### 11.5.5 Randomize kernel stack offset

```Nix
"randomize_kstack_offset=on"
```

Kernel stack offset randomization helps enhance security by introducing randomness into the stack memory layout for each process's kernel stack. Randomizing the kernel stack offset makes it more difficult for attackers to exploit certain types of vulnerabilities that rely on knowledge of the stack layout. Without randomization, an attacker might be able to craft an exploit more easily, as they would know the exact location of critical data structures in the kernel stack.


### 11.6 Avoid loading of insecure kernel modules
You can blacklist kernel modules which are not audited for security. Here is the list of some modules:

```Nix
  boot.blacklistedKernelModules = [
    # Obscure network protocols
    "ax25"
    "netrom"
    "rose"

    # Old or rare or insufficiently audited filesystems
    "adfs"
    "affs"
    "bfs"
    "befs"
    "cramfs"
    "efs"
    "erofs"
    "exofs"
    "freevxfs"
    "f2fs"
    "hfs"
    "hpfs"
    "jfs"
    "minix"
    "nilfs2"
    "ntfs"
    "omfs"
    "qnx4"
    "qnx6"
    "sysv"
    "ufs"
  ];
```

### 11.7 Configure systemd 
Configure systemd services to a 'safe' level with minimum exposure, make sure your service functionality is intact. Eposure of all the running services can be seen using below command:

```
$> systemd-analyze security
```

You can see profile of a service and how much a configuration is exposing the service to attacker using above command with service name as an additional parameter. For example the command for dbus service is:

```
$> systemd-analyze security debus.service
```


## 12. Conclusion
System security is a critical aspect of maintaining the confidentiality, integrity, and availability of information and resources within a computing environment. A robust security involves a combination of policies, technologies, and practices to safeguard against a wide range of threats, vulnerabilities, and potential attacks. 
It is a cat-and-mouse game between attackers and security professionals, attackers continuously devise new methods to compromise systems, while security experts work to fortify against these evolving threats. This ongoing process is not a one-time task; rather, it requires regular system audits and security updates for both known attacks and newly discovered vulnerabilities.

Security features in a Linux system can be managed through various avenues such as Kernel configuration, sysctl, kernel parameters, NixOS options, etc. It's important to note that selecting a security option in kernel configuration or NixOS is irreversible; to undo such a choice, one must undertake the process of recompiling the kernel or NixOS. In contrast, sysctl options can be modified at runtime, provided the user has privileged account access. It introduces a potential risk if attackers gain root privileges and manipulate sysctl. Adjusting kernel parameters through NixOS options requires a rebuild and system reboot. 

Kernel configurations are particularly robust in terms of security, as any disabled feature cannot be exploited by attackers even if they attain root privileges. Therefore, when configuring the security mechanisms of a system, it's crucial to carefully select the appropriate method based on specific requirements and consider the trade-offs associated with each approach.

### References:

https://madaidans-insecurities.github.io/guides/linux-hardening.html

https://tails.net/contribute/design/kernel_hardening/

https://www.tenable.com/audits

https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/profiles/hardened.nix


