# NixOS Hardening

## Authentication

Authentication plays a crucial role in safeguarding any system from potential threats. Before granting access to resources or data, it is essential to verify a user's identity to ensure authorized use of the system. Inadequate authentication measures can lead to severe consequences such as data breaches and security incidents. 

For an effectively hardened system, it is advisable to adopt a role-based authentication approach. This entails classifying users based on their roles and providing access to only the necessary information required for their tasks. By limiting access to specific areas, you can minimize the system's attack surface and decrease potential vulnerabilities.

To strengthen the authentication process, there are several best practices to follow, such as strong password policy, forcing privileged users to use multi-factor authentication, and using SSH keys for remote access. Additionally, implementing temporary account suspension after multiple failed login attempts can prevent unauthorized access.

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
