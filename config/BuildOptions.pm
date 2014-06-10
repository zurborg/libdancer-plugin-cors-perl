%BuildOptions = (%BuildOptions,
    NAME                => 'Dancer::Plugin::CORS',
    DISTNAME            => 'Dancer-Plugin-CORS',
    AUTHOR              => 'David Zurborg <zurborg@cpan.org>',
    VERSION_FROM        => 'lib/Dancer/Plugin/CORS.pm',
    ABSTRACT_FROM       => 'lib/Dancer/Plugin/CORS.pm',
    LICENSE             => 'open-source',
    PL_FILES            => {},
    PMLIBDIRS           => [qw[ lib ]],
    PREREQ_PM => {
        'Test::Most'        => 0,
		'Modern::Perl'      => 0,
		'Sub::Name'         => 0,
		'Dancer'            => 1.312,
		'URI'               => 1.6,
    },
    dist => {
        COMPRESS            => 'gzip -9f',
        SUFFIX              => 'gz',
        CI                  => 'git add',
        RCS_LABEL           => 'true',
    },
    clean               => { FILES => 'Dancer-Plugin-CORS-*' },
    depend => {
	'$(FIRST_MAKEFILE)' => 'config/BuildOptions.pm',
    },
);