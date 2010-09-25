#!/usr/bin/perl

use Net::FTP;
use Net::IP;
use Net::SMTP;
use MIME::Lite;

use Config::IniFiles;
use Getopt::Long;
use Data::Dumper;

use strict;
use warnings;

# Read  options command lines
my $help = 0;
GetOptions('help' => \$help);

if ( $help )
{
  print "Network quick scanner\n";
  print "nqscan [--help|--force-send|--config=<config-file>|--progress]\n";
}
else
{
  my $send;        # yes: force sending the report, auto: send the report only if there is warning(s)
  my $configPath;
  my $printProgress;

  GetOptions('force-send' => \$send, 'config=s' => \$configPath, 'print-progress' => \$printProgress);

  # When the option force-send is specified, the report will be sent anyway, even if there is no warning
  $send = $send ? 1 : 0;
  $configPath = '/etc/nqscan/config.ini' if !$configPath;

  # check if the file exists
  die "Config file is not existing ($configPath)" if ! -e $configPath; 

  # Read config file
  # my $config = Config::IniFiles->new(-file => $configPath);
  my %config;
  tie %config, 'Config::IniFiles', ( -file => $configPath );

  # read network parameters for the scan
  my $netParams = $config{'Network'};

  # overwritten paramters from the command line
  $netParams->{'PrintProgress'} = $printProgress ? '1' : '0';

  my $report = ScanNetwork($netParams, $send);

  if ( $send == 1 || $report->{'Alert'} == 1 ) {
    my $mailParams = $config{'Mail'};
    SendEmail($mailParams,$report);
  }
}


sub ScanNetwork
{
  my $params = shift;

  my @networks = split ',', $params->{'Networks'};
  my $waitTime = int($params->{'WaitTime'});
  my $printProgress = int($params->{'PrintProgress'});

  my @ipAddresses = ();    # full list of ip we'll scan
  my $details = '';        # text report to be sent
  my $warnings = '';       # warning text that'll be included ahead of the report
  my $alert = 0;           # Set to 1 if we need to send an alert by email or SMS, or something...!

  # build ip ranges list
  for my $network ( @networks )
  {
    my $iprange = new Net::IP($network);

    $details .= "\n\nScanned network: $network\n";

    do
    {
      my $ip = $iprange->ip();
      push @ipAddresses, $ip;

      my $status = 'not scanned';

      # Scan the host for FTP
      my $timedOut = 0;

      my $ftpClient = Net::FTP->new($ip, Debug => 0, Timeout => 10) or $timedOut = 1;

      if ( $timedOut == 1 )
      {
        $status = "Port Closed ot timeout.";
      }
      else
      {
        my $password = $params->{'Password'};
        my $user = $params->{'User'};

        if ( $ftpClient->login($user,$password) )
        {
          $alert = 1;
          $status = "Anonymous access enabled." ;

          $warnings .= "- $ip : $status\n";
        }
        else
        {
          $status = "Anonymous access disabled." ;
        }

        # test anonymous access
        $ftpClient->quit;
      }

      # for debugging purposes
      print "$ip: $status\n" if $printProgress;

      # Add line to the report
      $details .= "- $ip: $status\n";

      # Avoid network congestion
      sleep $waitTime if $waitTime;

    } while (++$iprange);
  }

  my %report = ( 'Alert' => $alert, 'Details' => $details, 'Warnings' => $warnings);

  return \%report;
}

sub SendEmail
{
  my $config = shift;
  my $report = shift;

  my $details = $report->{'Details'};
  my $warnings = $report->{'Warnings'};

  my $sign = $config->{'Signature'};
  my $from = $config->{'From'};
  my $to = $config->{'To'};
  my $smtpServer = $config->{'SmtpServer'};

  my $subject = "Network Quick Scan report";
  my $fullReport = "This is a network scan report from your network administrator.\n\n";
  $fullReport .= "One or more warning have been found:\n$warnings\n\n" if $warnings ne '';
  
  $fullReport .= "Detailled report: $details\n\n";
  $fullReport .= "-- \n$sign";

  my $msg = MIME::Lite->new (
    From => $from,
    To => $to,
    Subject => $subject,
    Type =>'multipart/mixed'
  ) or die "Error creating container: $!\n";

  $msg->attach (
    Type => 'TEXT',
    Data => $fullReport
  ) or die "Error adding the text message part: $!\n";

  MIME::Lite->send('smtp', $smtpServer, Timeout=>120);
  $msg->send;
}

