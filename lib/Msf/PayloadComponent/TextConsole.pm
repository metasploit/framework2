package Msf::PayloadComponent::TextConsole;
use strict;
use base 'Msf::Payload';
use IO::Handle;
use IO::Select;
use Msf::Logging;

sub Log {
	my $self = shift;
	$self->{'Log'} = shift if(@_);
	return($self->{'Log'});
}

sub _HandleConsole {
	my $self = shift;
	my $loop = 1;

	my $pLocalIn		= $self->PipeLocalIn;
	my $pLocalOut		= $self->PipeLocalOut;
	my $pRemoteIn		= $self->PipeRemoteIn;
	my $pRemoteOut		= $self->PipeRemoteOut;  

	$self->PipeWrite($pLocalOut, "\n");

	# Install the signal handler for the console
	my $sigHandler = sub {
		$self->PipeWrite($pLocalOut, "Caught ctrl-c, exit connection? [y/n] ");

		# Switch back to blocking mode for this read
		$pLocalIn->blocking(1);
		my $answer = $self->PipeRead($pLocalIn);	
		$pLocalIn->blocking(0);
		
		chomp($answer);
		if(lc($answer) eq 'y') {
			$loop = 0;
		}
	};

	# Save off the old handlers and replace with new
	my ($osigTerm, $osigInt) = ($SIG{'TERM'}, $SIG{'INT'});
	$SIG{'TERM'}	= $sigHandler;
	$SIG{'INT'}		= $sigHandler;

	# Non-blocking sockets. Wee.
	foreach ($pLocalIn, $pLocalOut, $pRemoteIn, $pRemoteOut) {
		$_->blocking(0);
		$_->autoflush(1);
	}

	# Open up the session log and write the header
	$self->StartLog;

LOOPER:

	while ($loop) {

		# Avoid interesting select bugs...
		my $selector = IO::Select->new($pLocalIn, $pRemoteOut);	
		
		# Check to see if the local or remote side have data
		my @ready = $selector->can_read;
		
		# No sockets are ready, sleep a little bit
		if (! scalar(@ready)) {
			select(undef, undef, undef, 0.5);
		}
		
		foreach my $ready (@ready) {
			
			# New data from the local console
			if ( $ready eq $pLocalIn ) {
			
				# Read the data from the console
				my $data = $self->PipeRead($pLocalIn);
				last LOOPER if ! defined($data);
			
				# Log the plain data before filter	
				$self->SendLog($data);
				
				# Convert the data if required
				$data = $self->SendFilter($data);

				# Write data back to the remote end
				my $ret = $self->PipeWrite($pRemoteIn, $data);
				last LOOPER if ! defined($ret);
			}
			
			# New data from the remote side
			elsif ( $ready eq $pRemoteOut ) {
			
				# Read the data from the remote end
				my $data = $self->PipeRead($pRemoteOut);				
				last LOOPER if ! defined($data);
				
				# Convert the data if required
				$data = $self->RecvFilter($data);
							
				# Log the converted data	
				$self->RecvLog($data);

				# Write data back to the console
				my $ret = $self->PipeWrite($pLocalOut, $data);
				last LOOPER if ! defined($ret);
			}
		}
		
		# Destroy the selector object
		undef($selector);
	}
	
	# Close down the session log
	$self->StopLog;

	# Switch back to the old signal handlers
	($SIG{'TERM'}, $SIG{'INT'}) = ($osigTerm, $osigInt);
}

sub SendFilter {
	my $self = shift;
	my $data = shift;
	return($data);
}

sub RecvFilter {
	my $self = shift;
	my $data = shift;
	return($data);
}

sub StartLog {
	my $self = shift;
	if(!$self->GetVar('Logging')) {
		$self->Log('');
		return;
	}

	my $logFile = time() . '_' . $self->GetVar('_Exploit')->SelfEndName . '_' . $self->PipeRemoteName . '.log';

	Msf::Logging->PrintLine('[' . localtime(time()) . '] ' . $self->GetVar('_Exploit')->SelfEndName . ' EXPLOIT SUCCESS');

	$self->Log(Msf::Logging->new($logFile));
	if(!$self->Log) {
		$self->PrintLine('[*] Error in logging, disabling.');
		$self->Log('');
		return;
	}

	my $headers = 'Time: ' . localtime(time()) . ' (' . time() . ")\n";
	$headers .= 'Name: ' . $self->GetVar('_Exploit')->Name . ' (' . $self->GetVar('_Exploit')->SelfName . ')' . "\n";
	
	$headers .= 'Options:';
	my $env = $self->GetEnv;
	foreach (keys(%{$env})) {
		my $key = $_;
		my $val = $env->{$key};
		next if(substr($key, 0, 1) eq '_' || ref($val));
		$val =~ s/"/\"/g;
		$headers .= qq{ $key="$val"};
	}
	$headers .= "\n";
 
	$headers .= 'PipeLocal: '.  $self->PipeLocalName  ." ( ". $self->PipeLocalSrc  .")\n";
	$headers .= 'PipeRemote: '. $self->PipeRemoteName ." ( ". $self->PipeRemoteSrc .")\n";

	$headers .= "\n";
	$self->Log->Print($headers);
	
	if ($self->Log->IsError) {
		$self->PrintLine('[*] Disabling logging: ' . $self->Log->GetError);
		$self->Log('');
		return;
	}
	
	Msf::Logging->PrintLine('[' . localtime(time()) . '] ' . $self->GetVar('_Exploit')->SelfEndName . ' SESSION LOG ' . $logFile);
}

sub StopLog {

}

sub SendLog {
	my $self = shift;
	my $data = shift;
	return if(!$self->Log);
	$self->Log->PrintLine(time() . ' CLIENT ' . unpack('H*', $data));
}

sub RecvLog {
	my $self = shift;
	my $data = shift;
	return if(!$self->Log);
	$self->Log->PrintLine(time() . ' SERVER ' . unpack('H*', $data));
}

1;
