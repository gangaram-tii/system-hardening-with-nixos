# Build a hardened system with NixOS

## Introduction

In today's digital age, protecting our computers and the information they hold is more important than ever. The motivations behind cyber attacks are as diverse as the individuals and groups who perpetrate them. Here are some of the most common reasons:

**Data breaches:** Hackers can steal sensitive information like passwords, financial data, or personal records, which can have devastating consequences.

**Identity theft:** Criminals can use stolen information to impersonate you, open fraudulent accounts, and ruin your credit.

**Ransomware attacks:** Malicious actors can encrypt your data and demand payment to unlock it, leaving you powerless without proper backups.

**System disruptions:** Viruses and malware can damage your computer, crash systems, and disrupt critical operations.

**Financial losses:** Data breaches, downtime, and cybercrime can cost businesses millions of dollars annually.

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
services.pam.services = {
  passwd = {
    text = ''
      password required pam_pwquality.so retry=3 minlen=12 difok=6 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 enforce_for_root
      password required pam_unix.so use_authtok shadow
    '';
  };
};
~~~

Or

~~~ Nix
security.pam.services.passwd = {
  enable = true;
  extraConfig = ''
    password required pam_pwquality.so retry=3 minlen=12 difok=6 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 enforce_for_root
  '';
};
~~~

This configuration enforces the following password requirements:

- Minimum length of 12 characters
- At least 6 characters must be different from the previous password
- At least one digit, one uppercase letter, and one lowercase letter
- At least one special character
- Passwords cannot contain the user’s name or username

You can modify these settings to suit your needs.

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


## 6. Harden Linux OS
Linux is a secure operating system that comes equipped with various built-in security subsystems by default to ensure the safety of your device. Two notable subsystems, namely SELinux (Security Enhanced Linux) and AppArmor, have been developed as Linux security module to offer enhanced security features.

NixOS employs a unique approach to package management and system configuration using the Nix language. Its focus is on immutability and reproducibility. 

SELinux assigns a security label to every file and process on the system. It stores security labels as extended attributes (xattrs) within the filesystem itself. Modifying files in the Nix store after they have been built to assign security labels etc. violates immutability. Supporting SELinux would require significant changes to the core principles of how NixOS manages its configurations and packages. However on the otherhand AppArmor is more compatible with Nix because it doesn't require attaching metadata to files.
