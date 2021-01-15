# mceggdrop
Mircryption (FiSH) for eggdrop with cbc/ecb encrypt method By SiteTechicien@GMail.com

This script (sometimes known as McEggdrop) can be added to your eggdrop
 scripts list, and it will allow all of your other scripts to speak encryped
 and understand text that has been encrypted by users.  See the actual script
 and settings file for more details.

# ChangeLog
View CHANGELOG.md

# Download
download to /home/<user>/eggdrop/scripts :

	git clone https://github.com/MalaGaM/mceggdrop.git /home/<user>/eggdrop/scripts

# Install
1) Copy these files to your eggdrop/scripts/ directory.
2) Add lines to your eggdrop .conf file
      # mircryption eggdrop
      source scripts/tcleggdrop_mcpsfuncs.tcl
3) Edit the tcleggdrop_mcps_sitesettings.ini file and modify it for your channels and preferences.
4) Restart/rehash your eggdrop.

# Upgrade
1) Copy these files to your eggdrop/scripts/ directory,
2) BUT do *NOT* overwrite any previous tcleggdrop_mcps_sitesettings.ini file you
 might already have configured for this script from a previous version if upgrading.
3) Retart your eggdrop OR login to partyline and do a .rehash.

# CONFLICTS WITH OTHER SCRIPTS
If you find that your bot will not respond to encrypted messages, it might be that you
have another script which might be intercepting +OK messages before mceggdrop has a chance to.

To see if this is the case, comment out the other scripts in your eggdrop config.

Once you confirm it is a script conflict, try to find the "bind pub ... +OK" in the other script,
and determine if you still need it now that you have mceggdrop installed, if not, comment out the bind. 

Nothing else about the script matters except for the bind statement.
One way to fix the other script is if you find it using 'bind pub'

then modify it to use 'bind pubm' style binding, which allows other scripts to still bind:
change from:  bind pub - "!command" function
to:           bind pubm -|- "* !command" function

Some examples of scripts that try to catch +OK and can conflict with mceggdrop:
newdir.tcl and dzsbot.tvl, both by b0unty, from ioftpd.com forums scripts by "perceps"