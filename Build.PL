use strict;
use warnings;
use Module::Build;

my $builder = Module::Build->new(
    module_name         => 'Ark::ActionClass::RequestToken',
    license             => 'perl',
    dist_author         => 'Ryo Miyake <ryo.studiom@gmail.com>',
    dist_version_from   => 'lib/Ark/ActionClass/RequestToken.pm',
    requires => {
        'Test::More' => 0,
        'version'    => 0,
    },
    add_to_cleanup      => [ 'Ark-ActionClass-RequestToken-*' ],
);

$builder->create_build_script();
