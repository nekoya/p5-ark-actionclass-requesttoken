use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'Ark::ActionClass::RequestToken',
    AUTHOR              => 'Ryo Miyake <ryo.studiom@gmail.com>',
    VERSION_FROM        => 'lib/Ark/ActionClass/RequestToken.pm',
    ABSTRACT_FROM       => 'lib/Ark/ActionClass/RequestToken.pm',
    PL_FILES            => {},
    PREREQ_PM => {
        'Test::More' => 0,
        'version'    => 0,
    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean               => { FILES => 'Ark-ActionClass-RequestToken-*' },
);
