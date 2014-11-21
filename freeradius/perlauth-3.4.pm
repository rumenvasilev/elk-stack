#!/usr/bin/perl

# All credits go to me :)

# version 3.4
# Changes:
#	3.3 - add fail-over case for AD server in ldapcheck(); We no longer exit with die, in case of error,
#		as it kills the radius server.
#
# For errors/suggestions -> ice4o@hotmail.com

#print "PLEASE ENABLE ALL RADIUSD LOGGING AND DISABLE ALL PRINTS\n";
#exit;

#use strict;
#use warnings;
#use diagnostics;
use DBI;
use DBD::Pg;
use Net::LDAP;
use Switch;
use POSIX qw/strftime/;;

require 5.8.8;

# This is very important! Without this script will not get the filled hashes from main.
our (%RAD_REQUEST, %RAD_REPLY, %RAD_CHECK, %RAD_CONFIG);
#use Data::Dumper;

#
# This the remapping of return values
#
use constant    RLM_MODULE_REJECT=>    0;#  /* immediately reject the request */
use constant    RLM_MODULE_FAIL=>      1;#  /* module failed, don't reply */
use constant    RLM_MODULE_OK=>        2;#  /* the module is OK, continue */
use constant    RLM_MODULE_HANDLED=>   3;#  /* the module handled the request, so stop. */
use constant    RLM_MODULE_INVALID=>   4;#  /* the module considers the request invalid. */
use constant    RLM_MODULE_USERLOCK=>  5;#  /* reject the request (user is locked out) */
use constant    RLM_MODULE_NOTFOUND=>  6;#  /* user not found */
use constant    RLM_MODULE_NOOP=>      7;#  /* module succeeded without doing anything */
use constant    RLM_MODULE_UPDATED=>   8;#  /* OK (pairs modified) */
use constant    RLM_MODULE_NUMCODES=>  9;#  /* How many return codes there are */

use constant {
	DEBUG_OPT	=>	'0',	# enable debugging
	RADTSFILE => '/usr/local/etc/raddb/radts.file'	# radius has changes
};

# Datatase configuration parameters for Postgre's IPPLAN
use constant {
	DB_HOST		=>	'1.1.1.1', #primary db /ro/
	DB_HOST2	=>	'1.1.1.2', #secondary db /ro/
	DB_RW_HOST	=>	'1.1.1.3',	#rw database
	DB_NAME		=>	'ipplan',
	DB_USER		=>	'ipplan',
	DB_PASS		=>	'ipplan',
	DB_TABLE	=>	'ipaddr',	# testipaddr (test) or ipaddr (prod)
	DB_TBL_BASE	=>	'base',
	DB_TBL_AREA	=>	'area',
	WIFIVLAN	=>	'WIFI-Users',
	RADIUS		=>	'radiussf',		# RADIUS
	LOCATION	=>	'Sofia',
	MAXMACCOUNT	=>	'3'			# Max mac address limit
};
# AD configuration parameters
use constant {
	AD_USER		=>	"cn=myradius,ou=service accounts,dc=ldapserver,dc=net",
	AD_PASS		=>	"myd3mop\@ssWord", #mydemopassword
	AD_HOST1	=>	'2.2.2.1',	# primary ldap
	AD_HOST2	=>	'2.2.2.3',	# secondary ldap
	AD_HOST3	=>	'2.2.2.4',  # thirnary ldap
	AD_PORT		=>	'3268',
	AD_BASE_1	=>	"dc=sof,dc=ldapserver,dc=net", # realm 1
	AD_BASE_2	=>	"dc=lon,dc=ldapserver,dc=net", # realm 2
	REALMS		=>	"LON,SOF"	 # realm name
};


#### rlm_perl: Added pair NAS-Port-Type = Wireless-802.11
#my $username = $RAD_REQUEST{'User-Name'};
#my $username = $ARGV[0];
#my $mac = $RAD_REQUEST{'Calling-Station-Id'};
#my $source = $RAD_REQUEST{'NAS-Port-Type'};

sub parseUsername
{

	my $username = $RAD_REQUEST{'User-Name'};
	my $source = $RAD_REQUEST{'NAS-Port-Type'};
	my $mac = $RAD_REQUEST{'Calling-Station-Id'};
	
	#my $username = $ARGV[0];	
	#my $mac = "00-21-5A-74-62-F2"; #Desktop PC
	#my $mac = "f0-de-f1-9d-13-e2";	#Notebook
	#my $mac = $ARGV[1];
	#print "$user, $realm, $mac\n";
	#$source = "Wireless-802.11";
	#my $source = "Ethernet";	
	
	if ($username =~ "/") {  # IPASS
		$prefix = "/";
	}
	if ($username =~ '\\\\\\\\') { #normally won't match
		$prefix = '\\\\\\\\';
	}
	if ($username =~ '\\\\') { # NTDomain (iPhone)
		$prefix = '\\\\\\\\';
	}

	my @res = split(/$prefix/, $username);
	
	#if (REALMS !~ $res[0]) {
#		$res[0] = "SOF";
#		$res[1] = $username;
#	}
	my @return_arr;
	push(@return_arr, $res[1], $res[0], $mac, $source);
	if (DEBUG_OPT) {
		&radiusd::radlog(1, "802.1x - DBG - Username is: $username. Prefix is $prefix.");
		&radiusd::radlog(1, "802.1x - DBG - Realm: $res[0], Account: $res[1].");
	}
	return @return_arr;
	#print "Username is: $username. Prefix is $prefix.\n";
	#print "Realm: $res[0], Account: $res[1].\n";

}


####
## AUTHORIZE TO CHECK MAC ADDRESS
####
#&authorization();
sub authorization () 
{

	my @hash = &parseUsername();
	$user = $hash[0];
	$realm = uc($hash[1]);
	$mac = parseMacAddr($hash[2]);
	$source = $hash[3];
	
	## IF REALM IS NOT DEFINED IN CONSTANT "REALMS" AND THE REQ COMES FROM ETHERNET SOURCE, THEN IT IS A MACHINEAUTH
	# change 2.8
	my @realmlist = split(/\,/, REALMS);
	my $r_check = 0;
	foreach (@realmlist) {
		if ($_ eq $realm) {
			$r_check = 1;
		}
	}

	## We check if the request comes from wired or wireless network
	# Wi-Fi = Wireless-802.11
	# Wired = Ethernet

	switch ($source) {
		case "Ethernet" {
			# check if it is a machine auth (change 2.8)
			if (!$r_check) {
				&radiusd::radlog(1, "MAC check - Unknown device. No realm found.");
				return RLM_MODULE_NOOP;
			}
			# check against the database
			my $macfuncheck = &macfuncshit($mac, $source);
			switch ($macfuncheck) {
				case "OK" {
					return RLM_MODULE_OK;
					}
				case "NOK" {
					return RLM_MODULE_REJECT;
					}
			}
		} # end case 1

		case "Wireless-802.11" {

			if (&macfuncshit($mac, $source) eq "OK") {
				return RLM_MODULE_OK;
			} else {				
				# Make sure the user exist
				#$user = "alexanderned";
				if (&VerifyADUser($user, $realm, 2) eq "OK") {
					# we run mac function to add the address into the database (wi-fi only!)
					if (&macaddr_ins($mac, $user, WIFIVLAN) eq "OK") {
						return RLM_MODULE_OK;
					} else {
						return RLM_MODULE_REJECT;
					}
				} else {	# NOK case
					#deny - incorrect credentials
					&radiusd::radlog(1, "802.1x - MAC check - incorrect username.");
					return RLM_MODULE_REJECT;
				}
			}
		} # end case 2
	} # end switch

}

####
## OUR POST_AUTH MODULE
####

## comment this when running from RADIUS
#&after_auth();
sub after_auth
{
	sleep(1);

	my @hash = &parseUsername();
	$user = $hash[0];
	$realm = uc($hash[1]);
	$mac = &parseMacAddr($hash[2]);
	#$source = $hash[3];
	$source = $RAD_REQUEST{'NAS-Port-Id'};
	#$source = "ethernet"; # testing

	if ($source =~ "radio") {
	
		&radiusd::radlog(1, "802.1x - Wireless connection, skipping VLAN check.");

	} else { #source is ethernet

		if (DEBUG_OPT) {
			&log_request_attributes;
		}

		# we have a special case
		# when it is a machine authentication, we have already defined VLAN
		# so we check for 'Extreme-Netlogin-Vlan' existence and if so, return ok
		if ($RAD_REPLY{'Extreme-Netlogin-Vlan'}) {
		
			&radiusd::radlog(1, "802.1x - VLAN already defined. It's a machine.");

		} else {

			my $vlan = &VerifyADUser($user, $realm, 1);
			
			if ($vlan eq "FAIL") {
				return RLM_MODULE_REJECT;
			} elsif ($vlan eq NULL) {
				&radiusd::radlog(1, "802.1x - No VLAN found!!!");
				return RLM_MODULE_REJECT;
			} elsif ($vlan eq "HOST") {
				&radiusd::radlog(1, "802.1x - It's a machine auth");
				$vlan = NULL;
			}

			#print "$realm\n";
			my $switchvlan = &mapvlan($vlan, $realm);
			#$RAD_REPLY{'Extreme-Netlogin-Vlan'} = $switchvlan; # Map the VLAN from AD to the switch database

			my $macvlancheck = &checkNotebook($mac, $switchvlan);
			#print "$macvlancheck\n";
			switch ($macvlancheck) {
				case "NOVLAN" {
					&radiusd::radlog(1, "802.1x - Found existing notebook record but not in ".LOCATION);
					#print "802.1x - Found existing notebook without a record in ".LOCATION."\n";
					#print "Going to macaddr insert with data mac: $mac, user: $user, vlan $switchvlan\n";
					if (&macaddr_ins($mac, $user, $switchvlan) ne "OK") {
						return RLM_MODULE_REJECT;
					}
					$RAD_REPLY{'Extreme-Netlogin-Vlan'} = "AuthFailed";
					return RLM_MODULE_OK;
				}
				case "OK" {
					&radiusd::radlog(1, "802.1x - Notebook record in correct VLAN.");
				}
				case "NOK" {
					&radiusd::radlog(1, "802.1x - Not identified as Notebook!");
					#&log_request_attributes();
				}
			}
			&radiusd::radlog(1, "802.1x - VLAN found - $vlan");
			$RAD_REPLY{'Extreme-Netlogin-Vlan'} = $switchvlan;
			#print &mapvlan($vlan, $realm)."\n";
		}
	}
	return RLM_MODULE_OK;

}

# /* PLEASE DO NOT MODIFY ANYTHING BELOW THIS LINE!!! */
#
# LINE :)



###
## BEGIN FUNCTIONS, DON'T MODIFY HERE!!!
### Verify user in AD
## Usage: VerifyADUser(search, realm, param);
## param -> 1 = return vlan name or NULL if wrong username
## param -> 2 = verify user only; return OK/NOK for true/false
sub VerifyADUser # this goes to post_auth();
{

	my ($search, $realm, $param) = @_;
	## PLEASE DEFINE THE REALM!!! EITHER SOF, EITHER LON
	switch ($param) {
		case 1 {	# request vlan
			if ($search =~ "ldapserver") { return "HOST"; }
			else {
				my $vlanad = &ldapcheck($realm, $search, 1); # Get the VLAN from AD
				&radiusd::radlog(1,"802.1x - Search phrase is $search");
				return $vlanad;
			}
		}
		case 2 {		# verify user
			return &ldapcheck($realm, $search, 2);
		}
	}

}

# Usage: ldapcheck(realm, useraccount, option);
# options: 1 = check vlan, 2 = check user exist
sub ldapcheck
{

	my ($realm, $srchacc, $option) = @_;
	my ($ldap, $ldap1, $ldap2, $ldap3);

	$ldap1 = Net::LDAP->new(AD_HOST1, port=>AD_PORT, timeout=>2); 	#or die "Could not create object: $@";
	
	if (!defined($ldap1)) {
		&radiusd::radlog(1, "802.1x - Can't connect to primary Active Directory server. Trying to fail-over.");
		$ldap2 = Net::LDAP->new(AD_HOST2, port=>AD_PORT, timeout=>2);
		if (!defined($ldap2)) {
			&radiusd::radlog(1, "802.1x - Can't connect to backup Active Directory server. Trying third server.");
			$ldap3 = Net::LDAP->new(AD_HOST3, port=>AD_PORT, timeout=>2);
			if (!defined($ldap3)) {
				&radiusd::radlog(1, "802.1x - Can't connect to backup Active Directory server. Rejecting the request.");
                        	return "FAIL";
			} else {
				$ldap = $ldap3;
			}
		} else {
			$ldap = $ldap2;
		}
	} else {
		$ldap = $ldap1;
	}
	my $mesg = $ldap->bind(AD_USER, password=>AD_PASS);
	if (!defined($mesg)) {
		&radiusd::radlog(1, "802.1x - Can't bind to Active Directory server. Credentials?");
		return "FAIL";
	}
	$mesg->code && die $mesg->error;

	# DEPENDING ON REALM SET THE APPROPRIATE DN (SOF,LON)
	my $base;
	if ($realm =~ "SOF") { $base = AD_BASE_1; }
	elsif ($realm =~ "LON") { $base = AD_BASE_2; } 
	my $srch = "(sAMAccountName=".$srchacc.")";
	$mesg = $ldap->search(base => $base,
									scope => 'sub',
									filter => $srch,
									attrs => ['memberof'],
									);
	$mesg->code && die $mesg->error; # in case of error

	switch ($option) {
		case 1 {
			if ($mesg->entries) {
				# get all OUs and filter ou=VLANs
				my @resarr;
				foreach my $entry ($mesg->entries) {
					@resarr = $entry->get_value('memberof');
				}
				#CN=HR_W,OU=Shares,OU=Workstations,DC=sof,DC=ldapserver,DC=net CN=HR_Advisors,OU=Groups,OU=HR,OU=Workstations,DC=sof,DC=ldapserver,DC=netCN=VLAN16 - General management,OU=VLANs,DC=sof,DC=ldapserver,DC=net
				my $i = 0;
				my $id;
				foreach (@resarr) {
					my @res = split(/,/, $_);
					if ($res[1] =~ "VLANs") {
						$id = $i;
					}
					$i++;
				}
	
				# @arraye[$id] contains the correct VLAN memberof result
				# CN=VLAN19 - System Administrator,OU=VLANs,DC=sof,DC=ldapserver,DC=net
				#print $resarr[$id];
				my @cn = split(/\,/, $resarr[$id]);
				my $vlancn = $cn[0];
				my @vlanname = split(/=/, $cn[0]);
				my $vlan = $vlanname[1];
				return $vlan;
			} else {
				# we ain't have a valid username, so we return directly null value
				&radiusd::radlog(1, "802.1x - Username is incorrect!");
				return NULL;
			}
		}	# end of case 1
		
		case 2 {
			if ($mesg->entries) {	# we have a positive result; now compare the input username with the output finding
				return "OK";
			} else {
				return "NOK";
			}		
		}	# end of case 2
	}	# end of switch
	
	$ldap->unbind;

}

##############
### USED IN POST_AUTH
##### VLAN ASSIGNMENT FUNCTION
# IN RESPONSE TO EXTREME SWITCHES
sub mapvlan($$) {
	# VLAN19 - System Administrator
	my ($vlanad, $realm) = @_;
	# We have to match $vlanad with the next predefined vlans
	switch ($realm)
	{
		case "LON" {
			switch ($vlanad) {
				case "VLAN - Management" { return "VL-Management"; }
				case "VLAN - Risk&Legal" { return "VL-RiskLegal"; }
				case "VLAN - Compliance" { return "VL-Compliance"; }
				case "VLAN - Finance" { return "VL-Finance"; }
				case "VLAN - Payments & Reconciliation" { return "VL-Payments"; }
				default { return "AuthFailed"; }
			}
		}
		case "SOF" {
			switch ($vlanad) {
				case "VLAN - Management" { return "VL-Management"; }
				case "VLAN - Risk&Legal" { return "VL-RiskLegal"; }
				case "VLAN - Compliance" { return "VL-Compliance"; }
				case "VLAN - Finance" { return "VL-Finance"; }
				case "VLAN - Payments & Reconciliation" { return "VL-Payments"; }
				default { return "AuthFailed"; }
			}
		}
		case "host" { return "MachineAuth"; }
		default { return "MachineAuth"; }
	}
}


##############
### USED IN AUTHORIZE SECTION PRIOR TO EAP SETUP
# MAC ADDRESS VERIFICATION FUNCTION
#####
# Usage: macfunshit($mac, $source) -> $mac = mac address, $source = Ethernet/Wireless-802.11
# 
sub macfuncshit ($) {
	my ($mac, $source) = @_;
	# PARSER FOR MAC ADDRESS
	# DB MAC IS aabbccddeeff FORMAT
	#print "$mac\n";
	my ($dbh, $dbh1, $dbh2);
	$dbh1 = DBI->connect("DBI:Pg:dbname=".DB_NAME.";host=".DB_HOST."", DB_USER, DB_PASS, {'RaiseError' => 0});
	if (!defined($dbh1)) {
		&radiusd::radlog(1, "802.1x - Can't connect to PostgreSQL database. Trying next server.");
		$dbh2 = DBI->connect("DBI:Pg:dbname=".DB_NAME.";host=".DB_HOST2."", DB_USER, DB_PASS, {'RaiseError' => 0});
		if (!defined($dbh2)) {
			&radiusd::radlog(1, "802.1x - Can't connect to PostgreSQL database. MAC check failed.");
			return &deny_user();
		} else {
			$dbh = $dbh2;
		}
	} else {
		$dbh = $dbh1;
	}
	# check source (change 2.6)
	my $sth;
	if ($source eq "Ethernet") {
		$sth = $dbh->prepare("SELECT macaddr from ".DB_TABLE." WHERE lower(macaddr)='$mac'");
	} else {
		# source is Wireless-802.11
		#check in Sofia. (change 2.5)
		$sth = $dbh->prepare("SELECT t1.macaddr from ".DB_TABLE." AS t1, ".DB_TBL_BASE." AS t2, ".DB_TBL_AREA." as t3
										WHERE t1.baseindex=t2.baseindex AND t2.customer=t3.customer AND lower(t1.macaddr)='$mac'
										AND t2.descrip='".WIFIVLAN."' AND t3.descrip='Sofia' LIMIT 1");
	}
	$sth->execute();
	my $res = $sth->rows;
	#print $res."\n";
	if ($res >= '1') {
		# raise radius flag to be parsed to post_auth
		&radiusd::radlog(1, "802.1x - MAC address was found.");
		#print "result OK\n";
		return &allow_user();

	} else {		# MAC DOES NOT EXIST, SO WE ADD ONE UNTIL A LIMIT OF 3 IS REACHED
		&radiusd::radlog(1, "802.1x - MAC does not exist in the database!");
		#print "result NOK\n";
		return &deny_user();
	}
	#disconnect
	$dbh->disconnect();
}

##############
### USED IN AUTHORIZE SECTION FOR WIFI USERS PRIOR TO EAP SETUP
### AND IN POST_AUTH FOR NOTEBOOK USERS AFTER EAP SETUP
#####
# MAC ADDRESS INSERTION FUNCTION
#####
# Usage: macaddr_ins(macaddr, AD username, VLAN)
# Return: OK/NOK
###
# Does not handle wrong vlans. Only inserts the data into the database!!!
#&macaddr_ins('aabbccddeeff', 'mynametest', 'VL-SA');
sub macaddr_ins
{	
	# get $mac and $username
	# $lookup = vlan name (VL-SA)
	my ($mac, $username, $lookup) = @_;
	my ($dbh, $dbh1, $dbh2);

	$dbh1 = DBI->connect("DBI:Pg:dbname=".DB_NAME.";host=".DB_HOST."", DB_USER, DB_PASS, {'AutoCommit' => 1,'RaiseError' => 0,'PrintError' => 0});
	if (!defined($dbh1)) {
		&radiusd::radlog(1, "802.1x - Can't connect to PostgreSQL database. Trying next server. Errno: 14");
		$dbh2 = DBI->connect("DBI:Pg:dbname=".DB_NAME.";host=".DB_HOST2."", DB_USER, DB_PASS, {'AutoCommit' => 1,'RaiseError' => 0,'PrintError' => 0});
		if (!defined($dbh2)) {
			&radiusd::radlog(1, "802.1x - Can't connect to PostgreSQL database. Errno: 14");
			return &deny_user();
		} else {
			$dbh = $dbh2;
		}
	} else {
		$dbh = $dbh1;
	}

	if ($lookup eq WIFIVLAN) {
		my ($sofianet, $sofiabase, $londonnet, $londonbase, $berlinnet, $berlinbase);
	}
	# defining all the vars we need in the function
	my ($subnetrange, $vlannet, $vlanbase, $maccountcurrent, $userinfo, $ip, $reserve);	
	#$userinfo = "DHCP".$username."-%";
	
	my $netqry = "SELECT t1.baseaddr , t1.subnetsize, t1.baseindex AS vlanindex, t2.descrip AS location
						FROM ".DB_TBL_BASE." AS t1, ".DB_TBL_AREA." AS t2 WHERE t1.customer=t2.customer AND t1.descrip='$lookup'";

	my $netex = $dbh->prepare($netqry);
	$netex->execute();

	while (my ($baseaddr, $subnetsize, $vlanindex, $location) = $netex->fetchrow_array()) {
		#print "$baseaddr, $subnetsize, $vlanindex, $location\n";
		# CASE if it is for the WIFI users (as we add records in multiple tables there).
		if ($lookup eq WIFIVLAN) {
			switch ($location)
			{
				case "Sofia" {
					$sofianet = $baseaddr;
					$sofiabase = $vlanindex; }
				case "London" {
					$londonnet = $baseaddr;
					$londonbase = $vlanindex; }
				case "Berlin" {
					$berlinnet = $baseaddr;
					$berlinbase = $vlanindex; }
			}
			$subnetrange = $subnetsize;
			
		} else { # all other VLANs
			# FIND OUR LOCATION
			if ($location eq LOCATION) {
				$vlannet = $baseaddr; # network
				$vlanbase = $vlanindex; # vlan base index
				$subnetrange = $subnetsize;
				last;
			}
		}
	}
	$netex->finish();

	#print "$vlannet\n$vlanbase\n";
	
	###
	## CHECK MAC MAX COUNT
	# ENSURE MAXMACCOUNT ISN'T REACHED!
	# *only* for WiFi!
	if ($lookup eq WIFIVLAN) {
		my $ensure = $dbh->prepare("SELECT COUNT(macaddr) AS mac FROM ".DB_TABLE." WHERE descrip='$username' AND baseindex=$sofiabase AND location='Sofia'");
		$ensure->execute();
		
		while (my $eres = $ensure->fetchrow_hashref()) {
			$maccountcurrent = $eres->{'mac'};
		}
		$ensure->finish();

		if ($maccountcurrent == MAXMACCOUNT) {
			&radiusd::radlog(1, "802.1x - User $username, reached maximum MAC addresses allowed - ".MAXMACCOUNT.".");		
			#print "MAX MAC COUNT - ".(MAXMACCOUNT).", REACHED!!!\n";
			return &deny_user();
		}
	}
	$userinfo = "DHCP".$username."-".$mac;

	#######
	# Get an IP address
	if ($lookup eq WIFIVLAN) {
		# Case WiFi
		$ip = &FindNextFree($dbh, $sofianet, $subnetrange, 1);
	} else {
		# Case Notebook		
		$ip = &FindNextFree($dbh, $vlannet, $subnetrange, 5);
	}

	if (!$ip) {
		## cannot allocate a free address
		&radiusd::radlog(1, "802.1x - Can't allocate a free address in the DB.");
		return &deny_user();
	}
	#print "FREE IP is: ".dec2ip($ip)." - $ip\n"; # Free IP in Sofia subnet

	
	## PRIOR TO RESERVATION, WE NEED TO MAKE NEW DB CONNECTION, AS THE R/W HOST IS ONLY IN SOFIA	
	if (LOCATION ne "Sofia") {
		#destroy DB connection and make new
		$dbh->disconnect();
		$dbh = DBI->connect("DBI:Pg:dbname=".DB_NAME.";host=".DB_RW_HOST."", DB_USER, DB_PASS, {'AutoCommit' => 1,'RaiseError' => 0,'PrintError' => 0});
		if (!defined($dbh)) {
			&radiusd::radlog(1, "802.1x - Can't connect to RW PostgreSQL database. Errno: 18");
			return &deny_user();
		}
	}

	##Reserve the IP
	if ($lookup eq WIFIVLAN) {
		# Case WiFi
		$reserve = &ReserveIP($dbh, $ip, $mac, $sofiabase, "Sofia");
	} else {
		# Case Notebook
		$reserve = &ReserveIP($dbh, $ip, $mac, $vlanbase, LOCATION);
	}
	if ($reserve =~ 'FAILED') {
		## CANNOT RESERVE THE IP ADDRESS, REJECT THE USER TO RETRY
		&radiusd::radlog(1, "802.1x - Can't preserve a free address in the DB.");
		return &deny_user();
	}
	
	# get the ip address only w/o the subnet it is in.
	my $iponly = $ip-$sofianet;
	my $iplon = $iponly+$londonnet;
	my $ipber = $iponly+$berlinnet;
	
	### HERE COMES DATABASE RECORD INSERT/UPDATE	
	## Update the database
	$dbh->{AutoCommit} = 0; #enable transactions
	$dbh->begin_work();
		
	my $sth;
	if ($lookup eq WIFIVLAN) {
		# WiFi case
		$sth = $dbh->prepare("SELECT addMacAddr($ip,$iplon,$ipber,'$userinfo','$username','$mac',$sofiabase,$londonbase,$berlinbase,'".RADIUS."')");
	} else {
		# Notebook case
		$sth = $dbh->prepare("SELECT addnotebook($ip,'$userinfo','Notebook','".LOCATION."','$mac',$vlanbase,'".RADIUS."')");
	}
	
	my $exec = $sth->execute();
	if (!$exec) {
		$dbh->rollback;
		# enter retry loop		
		my $i = 0;
		while ($i <= 1) {
			sleep(3);
			if (!$exec) {
				$dbh->rollback; # rollback and try again 2 more times in case the table was locked
				$i++;
			} else {
				# Adding data succeeded, so ALLOW the user
				&triggerDHCPgen();	# trigger dhcp regeneration
				&radiusd::radlog(1, "802.1x - MAC address added in the DB. Retry #$i");
				return &allow_user();
			}
		}
		$dbh->disconnect();
		# Cannot add the data in the DB so DENY the user to retry
		&radiusd::radlog(1, "802.1x - Can't insert the MAC address into the DB!");
		return &deny_user();
	} else {
		$dbh->commit();
		$sth->finish();
		$dbh->disconnect or warn "Disconnection failed: $DBI::errstr\n";
		## All fine so ALLOW the user
		&triggerDHCPgen();	# trigger dhcp regeneration
		&radiusd::radlog(1, "802.1x - MAC address added in the DB.");
		return &allow_user();
	}

}

### Find the next available address in Sofia subnet
## usage: FindNextFree(subnet, subnet range, offset);
sub FindNextFree
{

	my ($dbh, $baseaddr, $subnetsize, $offset) = @_;
    
	# order is important here!
	# Find all used addresses
	my $result = $dbh->prepare("SELECT ipaddr FROM ".DB_TABLE." ORDER BY ipaddr ASC");
	$result->execute();
   my $offset_subnet = 1;
   my @arr;
   while(my $row = $result->fetchrow_hashref()) {
		# existing in database
		if (($row->{'ipaddr'} >= $baseaddr+$offset)&&($row->{'ipaddr'} < $baseaddr+$subnetsize-$offset)) {
				push(@arr, $row->{'ipaddr'});
		}
	}
	
	my $cnt = 0;
	my ($i, $insert);
	# Find the first unused address amoung the used ones in array @arr.
	for ($i=$baseaddr+$offset; $i<$baseaddr+$subnetsize-$offset_subnet; $i++) {
		if ((defined($arr[$cnt]))&&($arr[$cnt] == $i)) {
			$cnt++;
		} else {
			last;
		}
	}
	
	$result->finish();
	return $i;
	
}

### Reserve the IP for our user
## usage: ReserveIP(dbconn, ipaddress); 
sub ReserveIP
{

	# We reserve the IP addresses in Sofia only, and then populate to the other two.
	# we put mac in telno because we need it as reference only
	my ($dbh, $ip, $mac, $base, $location) = @_;
	my ($query, $sth, $row);
	$query = "INSERT INTO ".DB_TABLE." (ipaddr,userinf,location,telno,baseindex,userid) VALUES ($ip,'RESERVED','$location','$mac',$base,'".RADIUS."')";
	$sth = $dbh->prepare($query);
	$row = $sth->execute();
	if (!$row) {
		$sth->finish();
		return "FAILED";
	} else {
		$sth->finish();
		return "RESERVED";
	}

}

sub allow_user
{
	return "OK";
}

sub deny_user
{
	return "NOK";
}

# IP ADDRESS CALCULATORS
sub dec2ip ($)
{
	join '.', unpack 'C4', pack 'N', shift;
}


sub ip2dec ($)
{
	unpack N => pack CCCC => split /\./ => shift;
}

sub triggerDHCPgen
{

	my $time = strftime('%s',localtime); #unixtime
	open(PRGTMP, ">".RADTSFILE."");
	printf PRGTMP $time;#curent timestamp
	close(PRGTMP);
		
}

sub log_request_attributes {
    # This shouldn't be done in production environments!
    # This is only meant for debugging!
    for (keys %RAD_REPLY) {
            &radiusd::radlog(1, "RAD_REPLY: $_ = $RAD_REPLY{$_}");
    }
    for (keys %RAD_CONFIG) {
            &radiusd::radlog(1, "RAD_CONFIG: $_ = $RAD_CONFIG{$_}");
    }
}

# Find if the user has correct vlan-mac mapping. We already know, he's got valid mac address
# Used in post_auth (after_auth) section
sub checkNotebook
{
	my ($mac, $vlan) = @_;
	my ($dbh, $selq, $sth, $execute, $rows, $nbk, $nflag, $flag);
	my ($dbh1, $dbh2);

	# All VLANs are VL-* so we check for this!
	if (($vlan !~ "VL-")||($vlan =~ "VL-CorpITAdmin")) {
		return "NOK";
	}
	#print "mac is $mac and vlan is $vlan\n";
	# Make DB connection
	$dbh1 = DBI->connect("DBI:Pg:dbname=".DB_NAME.";host=".DB_HOST."", DB_USER, DB_PASS, {'RaiseError' => 0});
	if (!defined($dbh1)) {
		&radiusd::radlog(1, "802.1x - Can't connect to PostgreSQL database. Trying next server.");
		$dbh2 = DBI->connect("DBI:Pg:dbname=".DB_NAME.";host=".DB_HOST2."", DB_USER, DB_PASS, {'RaiseError' => 0});
		if (!defined($dbh2)) {
			&radiusd::radlog(1, "802.1x - Can't connect to PostgreSQL database. MAC check failed.");
			return &deny_user();
		} else {
			$dbh = $dbh2;
		}
	} else {
		$dbh = $dbh1;
	}
	# select t1.userinf as employee, t2.descrip as vlan, t3.descrip as location, case when t1.descrip='Notebook' then '1' else '0' end as notebook
	#	 from ipaddr as t1, base as t2, area as t3 where t1.baseindex=t2.baseindex and t2.customer=t3.customer and t1.macaddr=lower('2c41388eafe5');
	
	# check whether there's a record of the user's mac address in the correct vlan.
	# if not, add it.
	# username syntax -> DHCPusername-macaddr
	
	# CHECK for MAC+Notebook flag
	$nbk = "SELECT CASE t1.descrip WHEN 'Notebook' THEN 1 ELSE 0 END AS vlan
		FROM ".DB_TABLE." AS t1, ".DB_TBL_BASE." AS t2
		WHERE t1.baseindex=t2.baseindex AND lower(t1.macaddr)=lower('$mac')
		AND t2.descrip='$vlan'";

	$sth = $dbh->prepare($nbk);
	$sth->execute();
	
	$nflag = $sth->fetchall_hashref('vlan');
	foreach my $kye ( keys(%{$nflag}) ) {
		if ($nflag->{$kye}->{'vlan'} eq '1') {
			$flag = 1;
			&radiusd::radlog(1, "802.1x - It's a notebook. Raising notebook flag.");
			#print "802.1x - It's a notebook. Raising notebook flag.\n";
		} else {
			$flag = 0;
		}
	}	
	
	if ($flag) {
		$selq = "SELECT t1.baseindex AS vlanindex, t3.descrip AS location
					FROM ".DB_TABLE." AS t1, ".DB_TBL_BASE." AS t2, ".DB_TBL_AREA." AS t3
					WHERE t1.baseindex=t2.baseindex AND t2.customer=t3.customer AND lower(t1.macaddr)='$mac'
					AND t3.descrip='".LOCATION."' AND t2.descrip='$vlan' LIMIT 1";

		$sth = $dbh->prepare($selq);
		$sth->execute();
		
		$rows = $sth->rows;
		if (!$rows) {
			# close DB connection
			$sth->finish();
			$dbh->disconnect();
			return "NOVLAN";
		} else {
			# close DB connection
			$sth->finish();
			$dbh->disconnect();
			return "OK";
		}
	} else {
		return "NOK";
	}
}

sub parseMacAddr
{
	my $mac = shift;
	$mac =~ s/://g;
	$mac =~ s/-//g;
	$mac = lc($mac);
	return $mac;
}
