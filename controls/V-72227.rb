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

control "V-72227" do
  title "The operating system must implement cryptography to protect the integrity
of Lightweight Directory Access Protocol (LDAP) authentication communications."
  desc  "
    Without cryptographic integrity protections, information can be altered by
unauthorized users without detection.

    Cryptographic mechanisms used for protecting the integrity of information
include, for example, signed hash functions using asymmetric cryptography enabling
distribution of the public key to verify the hash information while maintaining the
confidentiality of the key used to generate the hash.
  "
  impact 0.5
  tag "severity": "medium"
  tag "gtitle": "SRG-OS-000250-GPOS-00093"
  tag "gid": "V-72227"
  tag "rid": "SV-86851r2_rule"
  tag "stig_id": "RHEL-07-040180"
  tag "cci": "CCI-001453"
  tag "nist": ["AC-17 (2)", "Rev_4"]
  tag "check": "Verify the operating system implements cryptography to protect the
integrity of remote LDAP authentication sessions.

To determine if LDAP is being used for authentication, use the following command:

# grep -i useldapauth /etc/sysconfig/authconfig
USELDAPAUTH=yes

If USELDAPAUTH=yes, then LDAP is being used. To see if LDAP is configured to use
TLS, use the following command:

# grep -i ssl /etc/pam_ldap.conf
ssl start_tls

If the \"ssl\" option is not \"start_tls\", this is a finding."
  tag "fix": "Configure the operating system to implement cryptography to protect
the integrity of LDAP authentication sessions.

Set the USELDAPAUTH=yes in \"/etc/sysconfig/authconfig\".

Set \"ssl start_tls\" in \"/etc/pam_ldap.conf\"."

  authconfig = file('/etc/sysconfig/authconfig')
  if authconfig.file? and !authconfig.content.empty?
    if parse_config(authconfig.content).params['USELDAPAUTH'].downcase.eql? 'yes'
      # @todo - pam resource
      describe command('grep -i ssl /etc/pam_ldap.conf') do
        its('stdout.strip') { should match /^ssl start_tls$/}
      end
    end
  end
end
