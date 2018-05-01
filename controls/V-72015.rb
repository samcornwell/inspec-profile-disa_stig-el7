# encoding: utf-8
#

# TODO ENHANCE: 1. this needs to be enhanced, i.e. to check the right thing. like V-72017

EXEMPT_HOME_USERS = attribute(
  'exempt_home_users',
  description: 'These are `home dir` exempt interactive accounts',
  default: []
)

NON_INTERACTIVE_SHELLS = attribute(
  'non_interactive_shells',
  description: 'These shells do not allow a user to login',
  default: ["/sbin/nologin","/sbin/halt","/sbin/shutdown","/bin/false","/bin/sync"]
)

control "V-72015" do
  title "All local interactive user home directories defined in the /etc/passwd
file must exist."
  desc  "If a local interactive user has a home directory defined that does not
exist, the user may be given access to the / directory as the current working
directory upon logon. This could create a Denial of Service because the user
would not be able to access their logon configuration files, and it may give
them visibility to system files they normally would not be able to access."
  impact 0.5
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72015"
  tag "rid": "SV-86639r1_rule"
  tag "stig_id": "RHEL-07-020620"
  tag "cci": ["CCI-000366"]
  tag "documentable": false
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify the assigned home directory of all local interactive
users on the system exists.

Check the home directory assignment for all local interactive non-privileged
users on the system with the following command:

# cut -d: -f 1,3 /etc/passwd | egrep \":[1-9][0-9]{2}$|:[0-9]{1,2}$\"
smithj /home/smithj

Note: This may miss interactive users that have been assigned a privileged UID.
Evidence of interactive use may be obtained from a number of log files
containing system logon information.

Check that all referenced home directories exist with the following command:

# pwck -r
user 'smithj': directory '/home/smithj' does not exist

If any home directories referenced in \"/etc/passwd\" are returned as not
defined, this is a finding."
  tag "fix": "Create home directories to all local interactive users that
currently do not have a home directory assigned. Use the following commands to
create the user home directory assigned in \"/etc/ passwd\":

Note: The example will be for the user smithj, who has a home directory of
\"/home/smithj\", a UID of \"smithj\", and a Group Identifier (GID) of \"users
assigned\" in \"/etc/passwd\".

# mkdir /home/smithj
# chown smithj /home/smithj
# chgrp users /home/smithj
# chmod 0750 /home/smithj"
  tag "fix_id": "F-78367r1_fix"

  IGNORE_SHELLS = NON_INTERACTIVE_SHELLS.join('|')

  users.where{ !shell.match(IGNORE_SHELLS) && (uid >= 1000 || uid == 0)}.entries.each do |user_info|
    next if EXEMPT_HOME_USERS.include?("#{user_info.username}")
    describe directory(user_info.home) do
      it { should exist }
    end
  end
end
