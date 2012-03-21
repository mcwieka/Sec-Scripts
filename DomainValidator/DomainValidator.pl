#!/usr/bin/perl

use LWP::UserAgent;
use Log::Syslog::Fast;

#Get Command line input

$domainQs = $ARGV[0];
$rootDomain
="http://www.mcafee.com/threat-intelligence/domain/default.aspx?domain=";


#Create request
my $ua = new LWP::UserAgent;
$ua->agent("DomainValidator");
$ua->env_proxy;
my $req = new HTTP::Request GET => $rootDomain . $domainQs;

#Perform Request
my $res = $ua->request($req);

#Store contents of request
my @html = $res->content;

foreach $line (@html)
{
    while ($line =~
        m/\<img\sid\=\"ctl00\_mainContent\_imgRisk\"\stitle\=\"(.*?)\"/g)
    {
        my $risk = $1;
    }
}

my $cef = "CEF:0|DomainValidator|DomainValidator|1.0|100|Domain Validation"
. $domainQs . "|1|shost=" . $domainQs. " msg=" . $risk;

my $logger = Log::Syslog::Fast->new(LOG_UDP, , 514, LOG_DAEMON,
    LOG_NOTICE, "test", "test2" );
$logger->send($cef, time);
