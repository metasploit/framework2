#!/usr/bin/perl -T -I../lib -Ilib -w 

use strict;
use warnings;

use Test::MockClass qw{Pex Pex::NDR Pex::SMB Pex::Socket::Tcp Pex::Struct};
use Test::More;
plan( tests => 52 );

eval { require 'Pex/DCERPC.pm'; };
ok( !$@, 'require' );

ok( Pex::DCERPC->new(), 'new' );

is(
    Pex::DCERPC::UUID_to_Bin('6bffd098-a112-3610-9833-46c3f87e345a'),
    "\x98\xD0\xFF\x6B\x12\xA1\x10\x36\x98\x33\x46\xC3\xF8\x7E\x34\x5A",
    'UUID_to_Bin'
);
ok( !Pex::DCERPC::UUID_to_Bin( "A" x 30 ), "UUID_to_Bin - invalid uuid" );

# object interface
{
    my $dce = Pex::DCERPC->new();
    is(
        $dce->UUID_to_Bin('6bffd098-a112-3610-9833-46c3f87e345a'),
        "\x98\xD0\xFF\x6B\x12\xA1\x10\x36\x98\x33\x46\xC3\xF8\x7E\x34\x5A",
        'UUID_to_Bin (object wrapper)'
    );
}

ok(
    (Pex::DCERPC::Bind(
        Pex::DCERPC::UUID_to_Bin('6bffd098-a112-3610-9833-46c3f87e345a'), '1.0'
    ))[0],
    'bind'
);

ok( !Pex::DCERPC::Bind(), 'bind (without args)' );
ok(
    !Pex::DCERPC::Bind(
        Pex::DCERPC::UUID_to_Bin('6bffd098-a112-3610-9833-46c3f87e345a')
    ),
    'bind (without interface version)'
);
ok( !Pex::DCERPC::Bind( 'A', '1.1' ), 'bind (invalid UUID)' );

# ugly, yes... but it works for now
{
    my $expected =
"\x05\x00\x0B\x03\x10\x00\x00\x00\x48\x00\x00\x00\x00\x00\x00\x00\xD0\x16\xD0\x16\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x34\x12\x34\x12\x34\x12\x34\x12\x12\x34\x12\x34\x12\x34\x12\x34\x01\x00\x00\x00\x04\x5D\x88\x8A\xEB\x1C\xC9\x11\x9F\xE8\x08\x00\x2B\x10\x48\x60\x02\x00\x00\x00";
    is(
        (
            Pex::DCERPC::Bind(
                Pex::DCERPC::UUID_to_Bin('12341234-1234-1234-1234-123412341234'),
                '1.0'
            )
        )[0],
        $expected,
        'bind (validating data)'
    );
    is(
        (
            Pex::DCERPC::Bind(
                Pex::DCERPC::UUID_to_Bin('12341234-1234-1234-1234-123412341234'),
                '1'
            )
        )[0],
        $expected,
        'bind with short interface version (validating data)'
    );

    my $dce = Pex::DCERPC->new();
    is(
        (
            $dce->Bind(
                Pex::DCERPC::UUID_to_Bin('12341234-1234-1234-1234-123412341234'),
                '1.0'
            )
        )[0],
        $expected,
        'bind via object handle (validating data)'
    );
}

{
    my $dce = Pex::DCERPC->new();
    is( $dce->fault2string(5), 'nca_s_fault_access_denied', 'fault2failure 5' )
}

# autoload
{
    my $dce = Pex::DCERPC->new();
    $dce->username('bob');
    is( $dce->username, 'bob', 'AUTOLOAD => username' );
    $dce->password('bob1');
    is( $dce->password, 'bob1', 'AUTOLOAD => password' );
    $dce->domain('bob2');
    is( $dce->domain, 'bob2', 'AUTOLOAD => domain' );

    eval { $dce->autoload_should_fail('bob'); };
    like( $@, qr/undefined function/, 'AUTOLOAD => undefined function' );
}

{
    my $dce = Pex::DCERPC->new();

    is(
        $dce->build_handle(
            '6bffd098-a112-3610-9833-46c3f87e345a',
            '1.0', 'ncacn_ip_tcp', '10.4.10.10', 80
        ),
        '6bffd098-a112-3610-9833-46c3f87e345a:1.0@ncacn_ip_tcp:10.4.10.10[80]',
        'build_handle (ncacn_ip_tcp)'
    );
    is(
        $dce->build_handle(
            '6bffd098-a112-3610-9833-46c3f87e345a',
            '1.0', 'ncacn_np', '10.4.10.10', '\wkssvc'
        ),
        '6bffd098-a112-3610-9833-46c3f87e345a:1.0@ncacn_np:10.4.10.10[\wkssvc]',
        'build_handle (ncacn_np)'
    );
    is(
        $dce->build_handle(
            '6bffd098-a112-3610-9833-46c3f87e345a',
            '1.0', 'ncacn_ip_udp', '10.4.10.10', 1025
        ),
'6bffd098-a112-3610-9833-46c3f87e345a:1.0@ncacn_ip_udp:10.4.10.10[1025]',
        'build_handle (ncacn_ip_udp)'
    );
    is(
        $dce->build_handle(
            '6bffd098-a112-3610-9833-46c3f87e345a',
            '1.0', 'ncacn_http', '10.4.10.10', 2225
        ),
        '6bffd098-a112-3610-9833-46c3f87e345a:1.0@ncacn_http:10.4.10.10[2225]',
        'build_handle (ncacn_http)'
    );

    ok(
        !$dce->build_handle(
            '6bffd098-a112-3610-9833', '1.0',
            'ncacn_http',              '10.4.10.10',
            2225
        ),
        'build_handle invalid uuid'
    );
    ok(
        !$dce->build_handle(
            '6bffd098-a112-3610-9833-46c3f87e345a',
            '1.0', 'ncacn_bmc', '10.4.10.10', 2225
        ),
        'build_handle invalid protocol'
    );

    ok(
        eq_array(
            [
                $dce->parse_handle(
'6bffd098-a112-3610-9833-46c3f87e345a:1.0@ncacn_http:10.4.10.10[2225]'
                )
            ],
            [
                '6bffd098-a112-3610-9833-46c3f87e345a',
                '1.0', 'ncacn_http', '10.4.10.10', '2225'
            ]
        ),
        'parse_handle'
    );
    ok(
        eq_array(
            [
                $dce->parse_handle(
'6bffd098-a112-3610-9833-46c3f87e345a@ncacn_http:10.4.10.10[2225]'
                )
            ],
            [
                '6bffd098-a112-3610-9833-46c3f87e345a',
                '1.0', 'ncacn_http', '10.4.10.10', '2225'
            ]
        ),
        'parse_handle (no version)'
    );
    ok(
        !$dce->parse_handle(
            '6bffd098-a112-3610-9833-46c3f87e345a@ncacn_http:10.4.10.10['),
        'parse_handle invalid handle'
    );
}

# Mock Pex::SMB to test our handling of the data.  NOTE, this isn't a full and
# complete test suite... it tests the cases that I've actually seen on the
# wire.  More tests will come as more functionality is added.
{
    my $uuid    = 'afa8bd80-7d8a-11c9-bef4-08002b102989';
    my $version = '1.0';
    my $protocol = 'ncacn_np';
    my $host = '10.10.10.10';
    my $pipe    = '\bmc';


    my $mock = Test::MockClass->new('Pex::Socket::Tcp');
    
    my $constructor = sub {
        my $proto = shift;
        my $class = ref($proto) || $proto;
        my $self = {};
        return bless($self, $class);
    };
  
    $mock->defaultConstructor( 'foo' => 1); 
    $mock->addMethod('GetError', sub {return;});
    $mock->addMethod('IsError', sub {return;});

    my $mock2 = Test::MockClass->new('Pex::SMB');
    $mock2->constructor('new');
    $mock2->addMethod('new', $constructor);
    $mock2->addMethod('DefaultNBName', sub { return 'mynbname'; });

    my $mock3 = Test::MockClass->new('Pex::Struct');
    $mock3->constructor('new');
    $mock3->addMethod('new', $constructor);

    foreach my $func (qw(SMBSessionRequest Error SMBNegotiate SMBSessionSetup SMBTConnect SMBCreate LastFileID SMBTransNP SMBWrite)) {
        # want to print what they call for an arg?  use this one:
        $mock2->addMethod($func, sub {
            my ($self, @args) = @_; 
            my $string = "$func => \n";
            foreach my $arg (@args) {
                $string .= "\t" . Pex::DCERPC::bin2hex($arg) . "\n";
            }
            warn "$string";
            return;
        });
        $mock2->addMethod($func, sub {return;});
    }
    my @calls = (qw(new SMBSessionRequest Error SMBNegotiate Error SMBSessionSetup Error DefaultNBName SMBTConnect Error SMBCreate Error LastFileID SMBTransNP Error));
    $mock2->setCallOrder(@calls);

    my $handle = Pex::DCERPC::build_handle($uuid, $version, $protocol, $host, $pipe);
    ok($handle, "mock handle ($protocol)");
    my $dce = Pex::DCERPC->new('handle' => $handle);
    ok($handle, "mock new ($protocol)");

    my $firstObjectId = $mock2->getNextObjectId();

    my $object = $mock2->getNextObjectId(); # this one, we ignore;
    $object = $mock2->getNextObjectId(); #  || 0;
    ok($mock2->verifyCallOrder($object), 'mock call order new (ncacn_np)');

    ok(
        eq_array(
            [$mock2->getArgumentList($object, 'SMBSessionRequest', 0)],
            ["\x2A\x53\x4D\x42\x53\x45\x52\x56\x45\x52"],
        ), 
        'SMBSessionRequest (ncacn_np)',
    );

    ok(
        eq_array(
            [$mock2->getArgumentList($object, 'SMBTConnect', 0)],
            ['\\\\mynbname\\IPC$']
        ),
        'SMBTConnect (ncacn_np)'
    );

    ok(
        eq_array(
            [$mock2->getArgumentList($object, 'SMBTransNP', 0)],
            ["\x05\x00\x0B\x03\x10\x00\x00\x00\x48\x00\x00\x00\x00\x00\x00\x00\xD0\x16\xD0\x16\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x80\xBD\xA8\xAF\x8A\x7D\xC9\x11\xBE\xF4\x08\x00\x2B\x10\x29\x89\x01\x00\x00\x00\x04\x5D\x88\x8A\xEB\x1C\xC9\x11\x9F\xE8\x08\x00\x2B\x10\x48\x60\x02\x00\x00\x00"]
        ),
        'bind (ncacn_np)'
    );
    
    my $response = "\x05\x00\x02\x03\x10\x00\x00\x00\x5C\x00\x00\x00\x00\x00\x00\x00\x44\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x01\x00\x54\x01\x04\x80\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    my $stub = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x01\x00\x54\x01\x04\x80\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

    $mock3->addMethod('Get', sub { return $response });
    $mock2->addMethod('SMBTransNP', sub {return Pex::Struct->new();});

    ok($dce->request($handle, 0, "A" x ((256 * 3) - 1)), "request (mock $protocol)");
    is($dce->{'response'}->{'StubData'}, $stub, "request response stub (mock $protocol)");
    is($dce->{'response'}->{'Type'}, 'response', "request response type (mock $protocol)");

    push (@calls, qw(LastFileID SMBWrite LastFileID SMBWrite LastFileID SMBTransNP));
    $mock2->setCallOrder(@calls);
    ok($mock2->verifyCallOrder($object), 'request with mocked Pex::SMB (ncacn_np)');
   
    ok(
        eq_array(
            [$mock2->getArgumentList($object, 'SMBWrite', 0)],
            [0, "\x05\x00\x00\x01\x10\x00\x00\x00\x18\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"]
        ),
        "request frag 1 (mock $protocol)"
    );
    
    ok(
        eq_array(
            [$mock2->getArgumentList($object, 'SMBWrite', 1)],
            [280, "\x05\x00\x00\x00\x10\x00\x00\x00\x18\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"]
        ),
        "request frag 2 (mock $protocol)"
    );

    
    ok(
        eq_array(
            [$mock2->getArgumentList($object, 'SMBTransNP', 1)],
            ["\x05\x00\x00\x02\x10\x00\x00\x00\x17\x01\x00\x00\x00\x00\x00\x00\xFF\x00\x00\x00\x00\x00\x00\x00\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"],
        ),
        "request frag 3 (mock $protocol)"
    );
        
    my $bad_response = "\x05\x00\x03\x03\x10\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xF7\x06\x00\x00\x00\x00\x00\x00";
    $mock3->addMethod('Get', sub { return $bad_response });
    ok($dce->request($handle, 0, "\xFF\xFF\xFF\xFF"), "request with fault(mock $protocol)");
    is($dce->{'response'}->{'Type'}, 'fault', "request with fault response type (mock $protocol)");
    is($dce->{'response'}->{'Error'}, 'nca_s_fault_ndr', "request with fault fault type (mock $protocol)");
}

# Mock Pex::Socket::TCP to test our handling of the data.  NOTE, this isn't a
# full and complete test suite... it tests the cases that I've actually seen on
# the wire.  More tests will come as more functionality is added.
{
    my $uuid    = 'afa8bd80-7d8a-11c9-bef4-08002b102989';
    my $version = '1.0';
    my $protocol = 'ncacn_ip_tcp';
    my $host = '10.10.10.10';
    my $pipe    = '\bmc';

    my $mock = Test::MockClass->new('Pex::Socket::Tcp');
    
    my $constructor = sub {
        my $proto = shift;
        my $class = ref($proto) || $proto;
        my $self = {};
        return bless($self, $class);
    };
  
    $mock->defaultConstructor( 'foo' => 1);
    foreach my $func (qw(Send IsError)) {
        $mock->addMethod($func, sub {
            my ($self, @args) = @_; 
            my $string = "$func => \n";
            foreach my $arg (@args) {
                $string .= "\t" . Pex::DCERPC::bin2hex($arg) . "\n";
            }
            warn "$string";
            return;
        });
        $mock->addMethod($func, sub {return;});
    }

 
    my $bind_response = "\x05\x00\x0C\x03\x10\x00\x00\x00\x44\x00\x00\x00\x01\x00\x00\x00\xB8\x10\xB8\x10\x43\xB9\x00\x00\x0D\x00\x5C\x50\x49\x50\x45\x5C\x6E\x74\x73\x76\x63\x73\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x04\x5D\x88\x8A\xEB\x1C\xC9\x11\x9F\xE8\x08\x00\x2B\x10\x48\x60\x02\x00\x00\x00";

    $mock->addMethod('Recv', sub {return $bind_response;});
    $mock->addMethod('Send', sub {return 1;});

    $mock->setCallOrder(qw(new IsError Send Recv Recv));

    my $handle = Pex::DCERPC::build_handle($uuid, $version, $protocol, $host, $pipe);
    ok($handle, "handle (mock $protocol)");

    my $dce = Pex::DCERPC->new('handle' => $handle);
    ok($dce, "new (mock $protocol)");

    my $firstObjectId = $mock->getNextObjectId();
    my $object = $mock->getNextObjectId(); # this one, we ignore;
    $object = $mock->getNextObjectId(); #  || 0;
  
    ok($mock->verifyCallOrder($object), "call order (mock $protocol)");

    ok(
        eq_array(
            [$mock->getArgumentList($object, 'Send', 0)],
            ["\x05\x00\x0B\x03\x10\x00\x00\x00\x48\x00\x00\x00\x00\x00\x00\x00\xD0\x16\xD0\x16\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x00\x80\xBD\xA8\xAF\x8A\x7D\xC9\x11\xBE\xF4\x08\x00\x2B\x10\x29\x89\x01\x00\x00\x00\x04\x5D\x88\x8A\xEB\x1C\xC9\x11\x9F\xE8\x08\x00\x2B\x10\x48\x60\x02\x00\x00\x00"],
        ), 
        "Send ($protocol)",
    );

    # get a "good" response with stub data
    {
        my $response = "\x05\x00\x02\x03\x10\x00\x00\x00\x5C\x00\x00\x00\x00\x00\x00\x00\x44\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x01\x00\x54\x01\x04\x80\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        my $stub = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x00\x01\x00\x54\x01\x04\x80\x01\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        $mock->addMethod('Recv', sub {return $response;});
        ok($dce->request($handle, 0, "\xFF\xFF\xFF\xFF"), "request (mock $protocol)");
        is($dce->{'response'}->{'Type'}, 'response', "request response type (mock $protocol)");
        is($dce->{'response'}->{'StubData'}, $stub, "request response stub (mock $protocol)");
    }

    # get a "bad" response with a fault
    {
        my $response = "\x05\x00\x03\x03\x10\x00\x00\x00\x20\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xF7\x06\x00\x00\x00\x00\x00\x00";
        $mock->addMethod('Recv', sub {return $response;});
        ok($dce->request($handle, 0, "\xFF\xFF\xFF\xFF"), "request with fault (mock $protocol)");
        is($dce->{'response'}->{'Type'}, 'fault', "request with fault response type (mock $protocol)");
        is($dce->{'response'}->{'Error'}, 'nca_s_fault_ndr', "request with fault fault type (mock $protocol)");
    }
}
