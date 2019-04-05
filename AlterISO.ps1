# paths to media.
#$media = 'c:\tasksequencemedia'
#$old   = "C:\Users\admin\Desktop\Untitled.iso"
$new   = "C:\Users\admin\Desktop\VisualStudioEnt2017.iso" #ISO file name

# paths to tools.
$tools    = 'C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\oscdimg'
$oscdimg  = "$tools\oscdimg.exe"
#$etfsboot = "$tools\etfsboot.com"
#$efisys   = "$tools\efisys.bin"

# mount the existing iso.
#$mount = mount-diskimage -imagepath $old -passthru

# get the drive letter assigned to the iso.
#$drive = ($mount | get-volume).driveletter + ':'

# create a temp folder for extracting the existing iso.
#$workspace = "{0}\{1}" -f $env:temp, [system.guid]::newguid().tostring().split('-')[0]
$workspace = "C:\VisualStudioEnt2017" #Folders/Files to create ISO
#new-item -type directory -path $workspace

# extract the existing iso to the temporary folder.
#copy-item $drive\* $workspace -force -recurse

# remove the read-only attribtue from the extracted files.
get-childitem $workspace -recurse | %{ if (! $_.psiscontainer) { $_.isreadonly = $false } }

# pause here... make manual updates to the extracted iso.
#read-host

# create the updated iso.
#$data = '2#p0,e,b"{0}"#pEF,e,b"{1}"' -f $etfsboot, $efisys
#start-process $oscdimg -args @("-bootdata:$data",'-u2','-udfver102', $workspace, $new) -wait -nonewwindow
start-process $oscdimg -args @('-u2','-udfver102', $workspace, $new) -wait -nonewwindow

# remove the extracted content.
#remove-item $workspace -recurse -force

# dismount the iso.
#dismount-diskimage -imagepath $old
Write-Host "OK" -ForegroundColor Green