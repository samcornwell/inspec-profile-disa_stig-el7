# encoding: utf-8
#
=begin
-----------------
Benchmark: Red Hat Enterprise Linux 7 Security Technical Implementation Guide
Status: Accepted

This Security Technical Implementation Guide is published as a tool to improve
the security of Department of Defense (DoD) information systems. The
requirements are derived from the National Institute of Standards and
Technology (NIST) 800-53 and related documents. Comments or proposed revisions
to this document should be sent via email to the following address:
disa.stig_spt@mail.mil.

Release Date: 2017-03-08
Version: 1
Publisher: DISA
Source: STIG.DOD.MIL
uri: http://iase.disa.mil
-----------------
=end
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

control "V-72025" do
  title "All files and directories contained in local interactive user home
directories must be group-owned by a group of which the home directory owner is a
member."
  desc  "If a local interactive user’s files are group-owned by a group of which the
user is not a member, unintended users may be able to access them."
  impact 0.5

  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": "V-72025"
  tag "rid": "SV-86649r1_rule"
  tag "stig_id": "RHEL-07-020670"
  tag "cci": "CCI-000366"
  tag "nist": ["CM-6 b", "Rev_4"]
  tag "check": "Verify all files and directories in a local interactive user home
directory are group-owned by a group the user is a member of.

Check the group owner of all files and directories in a local interactive user’s
home directory with the following command:

Note: The example will be for the user \"smithj\", who has a home directory of
\"/home/smithj\".

# ls -lLR /<home directory>/<users home directory>/
-rw-r--r-- 1 smithj smithj  18 Mar  5 17:06 file1
-rw-r--r-- 1 smithj smithj 193 Mar  5 17:06 file2
-rw-r--r-- 1 smithj sa        231 Mar  5 17:06 file3

If any files are found with an owner different than the group home directory user,
check to see if the user is a member of that group with the following command:

# grep smithj /etc/group
sa:x:100:juan,shelley,bob,smithj
smithj:x:521:smithj

If the user is not a member of a group that group owns file(s) in a local
interactive user’s home directory, this is a finding."
  tag "fix": "Change the group of a local interactive user’s files and directories
to a group that the interactive user is a member of. To change the group owner of a
local interactive user’s files and directories, use the following command:

Note: The example will be for the user smithj, who has a home directory of
\"/home/smithj\" and is a member of the users group.

# chgrp users /home/smithj/<file>"

  IGNORE_SHELLS = NON_INTERACTIVE_SHELLS.join('|')

  findings = Set[]
  users.where{ !shell.match(IGNORE_SHELLS) && (uid >= 1000 || uid == 0)}.entries.each do |user_info|
    next if EXEMPT_HOME_USERS.include?("#{user_info.username}")
    find_args = ""
    user_info.groups.each { |curr_group|
      # some key files and secure dirs (like .ssh) are group owned 'root'
      find_args = find_args + "-not -group #{curr_group} -o root"
    }
    findings = findings + command("find #{user_info.home} #{find_args}").stdout.split("\n")
  end
  describe "Home directory files with incorrect group ownership or not 'root' owned" do
    subject { findings.to_a }
    it { should be_empty }
  end
end
