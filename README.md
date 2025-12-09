# CyberPatriot
#SudoAuditor
Revokes sudo privileges to all users except the ones added as an argument. Made for Ubuntu.

Example of use (Must be sudo):
sudo ./SudoAuditor.sh mario peach yoshi

All other users will be given normal admin rights.

#SudoViewer 
Just views all sudo users without all the garbage.

#PrivTester
Ensures that programs have correct permission structures after using SudoAuditor.

#Apache2.conf
Drag this pre-configured file to harden apache2
/etc/apache2/apache2.conf
#000 
Drag this pre-configured file to harden apache2
/etc/apache/sites-available/
