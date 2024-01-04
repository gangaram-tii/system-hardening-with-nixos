# NixOS Hardening

## Authentication

Authentication plays a crucial role in safeguarding any system from potential threats. Before granting access to resources or data, it is essential to verify a user's identity to ensure authorized use of the system. Inadequate authentication measures can lead to severe consequences such as data breaches and security incidents. 

For an effectively hardened system, it is advisable to adopt a role-based authentication approach. This entails classifying users based on their roles and providing access to only the necessary information required for their tasks. By limiting access to specific areas, you can minimize the system's attack surface and decrease potential vulnerabilities.

To strengthen the authentication process, there are several best practices to follow, such as strong password policy, forcing privileged users to use multi-factor authentication, and using SSH keys for remote access. Additionally, implementing temporary account suspension after multiple failed login attempts can prevent unauthorized access.

### Enforce Strong Password
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

### Enable Multifactor Authentication (MFA)
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

## Remote Access
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
