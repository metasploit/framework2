#!/usr/bin/perl
###############

##
#         Name: PsuedoShell.pm
#       Author: spoonm <spoonm [at] ghettohackers.net>
#       Author: H D Moore <hdm [at] metasploit.com> (minor updates)
#      Version: $Revision$
#      License:
#
#      This file is part of the Metasploit Exploit Framework
#      and is subject to the same licenses and copyrights as
#      the rest of this package.
#
##

package Pex::PsuedoShell;
use strict;
use Term::ReadLine;

sub new {
  my $term = Term::ReadLine->new($_[1]);
  if($term->ReadLine =~ /Stub/) {
    print "Using " . $term->ReadLine . ", I suggest installing something better (ie Term::ReadLine::Gnu)\n";
  }
  return(bless(
    {
      __PACKAGE__.'term' => $term,
      __PACKAGE__.'prompt' => $_[2],
      __PACKAGE__.'env' => { },
    }, shift)
  );
}
sub _term {
  my $self = shift;
  $self->{__PACKAGE__.'term'} = shift if(@_);
  return($self->{__PACKAGE__.'term'});
}

sub _prompt {
  my $self = shift;
  $self->{__PACKAGE__.'prompt'} = shift if(@_);
  return($self->{__PACKAGE__.'prompt'});
}
sub _env {
  my $self = shift;
  $self->{__PACKAGE__.'env'} = shift if(@_);
  return($self->{__PACKAGE__.'env'});
}

sub getEnv {
  my $self = shift;
  if(@_) {
    return($self->_env->{shift});
  }
  return($self->_env);
}

sub cprint {
  my $self = shift;
  my $out = $self->out;
  print $out @_;
}

sub out {
  my $self = shift;
  return($self->_term->OUT);
}

sub readCommand {
  my $self = shift;
  while(1) {
    my $line = $self->_term->readline($self->_prompt);
    next if(length($line) == 0);
    $line =~ s/^\s*//g;
    $line =~ s/\s*$//g;
    $line =~ s/\$([^\s]+)/$self->_env->{$1}/eg;
    my ($command, @args) = $self->parseCommands($line);
    if($command eq 'set') {
      if(@args == 1) {
        print "$args[0]: " . $self->_env->{$args[0]} . "\n";
      }
      elsif(@args == 2) {
        print "$args[0] -> $args[1]\n";
        $self->_env->{$args[0]} = $args[1];
      }
      else {
        my $env = $self->_env;
        foreach (sort(keys(%$env))) {
          print "$_: $env->{$_}\n";
        }
      }
      next;
    }
    return($command, @args);
  }
}

sub parseCommands {

  my $self = shift;
  my $text = shift;

  my @fields;
  my $field;
  my $quote;
  my $slash = 0;
  foreach(split('', $text)) {
    if($slash) { $field .= $_; $slash = 0; next; }
    if($_ eq '\\') { $slash = 1; next; }

    if(!$quote && $_ eq ' ') {
      push(@fields, $field) if(defined($field));
      $field = undef;
      next;
    }

    if($_ eq "'" || $_ eq '"') {
      if(!$quote)      { $quote = $_; next; }
      if($quote eq $_) { $quote = ''; next; }
    }
    $field .= $_;
  }
  push(@fields, $field) if(defined($field));
  return(@fields);
}

sub tabCompletion {
    my $self = shift;
    my $func = shift;    
    my $cattr = $self->_term->Attribs;
    $cattr->{attempted_completion_function} = $func;
}
1;
