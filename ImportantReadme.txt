//---------------------------------------------------------------------------
ABOUT THIS SCRIPT:
This script (sometimes known as McEggdrop) can be added to your eggdrop
 scripts list, and it will allow all of your other scripts to speak encryped
 and understand text that has been encrypted by users.  See the actual script
 and settings file for more details.
//---------------------------------------------------------------------------






//---------------------------------------------------------------------------
FIRST TIME INSTALL:

1) Copy these files to your eggdrop/scripts/ directory.
2) Add lines to your eggdrop .conf file, in the ##### SCRIPTS ##### section,
    below the lines to include alltools.tcl and action.fix.tcl:
      # mircryption eggdrop
      source scripts/tcleggdrop_mcpsfuncs.tcl
3) Edit the tcleggdrop_mcps_sitesettings.ini file and modify it for your
    channels and preferences.
3) Restart your eggdrop.
//---------------------------------------------------------------------------







//---------------------------------------------------------------------------
UPGRADE INSTRUCTIONS:

1) Copy these files to your eggdrop/scripts/ directory,
2) BUT do *NOT* overwrite any previous tcleggdrop_mcps_sitesettings.ini file you
 might already have configured for this script from a previous version if upgrading.
3) Retart your eggdrop OR login to partyline and do a .rehash.
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
Since version 1.00.17 (06/23/04), all user settings specifying keys for channels etc.,
 are now specified in a separate file (tcleggdrop_mcps_sitesettings.tcl).
You should not have to modify anything in the main tcleggdrop_mcpsfuncs.tcl file,
 and this change will allow you to upgrade the main script without it effecting any of your settings.

JUST REMEMBER:
 do *NOT* overwrite your existing tcleggdrop_mcps_sitesettings.tcl file
 when upgrading, or you will overwrite your settings with default values.
//---------------------------------------------------------------------------

//---------------------------------------------------------------------------
Since version 1.00.13 (05/08/04), tcleggdrop_mcpfuncs.tcl now requires that when specifying channel keys, you MUST
 specify your channel name in lowercase.
 
in other words, if your channel name is #MyChan
and in previous versions you had:
  set mcpskey(#MyChan)
you should now change this to:
  set mcpskey(#mychan)

Failure to do so will result in the new mceggdrop not finding the key for your channel.
//---------------------------------------------------------------------------



//---------------------------------------------------------------------------
Security note about setting keys on your eggdrop:
http://www.egghelp.org/faq.htm#038
//---------------------------------------------------------------------------



#######################################################
# CONFLICTS WITH OTHER SCRIPTS:
# If you find that your bot will not respond to encrypted messages, it might be that you
#  have another script which might be intercepting +OK messages before mceggdrop has a chance to.
# To see if this is the case, comment out the other scripts in your eggdrop config.
# Once you confirm it is a script conflict, try to find the "bind pub ... +OK" in the other script,
#  and determine if you still need it now that you have mceggdrop installed, if not, comment out the bind. 
# Nothing else about the script matters except for the bind statement.
# One way to fix the other script is if you find it using 'bind pub'
#  then modify it to use 'bind pubm' style binding, which allows other scripts to still bind:
# change from:  bind pub - "!command" function
# to:           bind pubm -|- "* !command" function
# Some examples of scripts that try to catch +OK and can conflict with mceggdrop:
#  newdir.tcl and dzsbot.tvl, both by b0unty, from ioftpd.com forums
#  scripts by "perceps"
#######################################################