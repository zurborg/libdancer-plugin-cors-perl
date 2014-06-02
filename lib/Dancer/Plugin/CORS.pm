package Dancer::Plugin::CORS;

use Modern::Perl;

=head1 NAME

Dancer::Plugin::CORS - A plugin for using cross origin resource sharing

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 DESCRIPTION

...

=head1 SYNOPSIS

    use Dancer::Plugin::CORS;

    get '/foo' => sub { ... }
	share '/foo' =>
		origin => 'http://localhost/',
		credentials => 1,
		expose => [qw[ Content-Type ]],
		method => 'GET',
		headers => [qw[ X-Requested-With ]],
		maxage => 7200,
	;

=cut

use Carp qw(croak confess);
use Dancer ':syntax';
use Dancer::Plugin;
use Sub::Name;
use URI;

my $routes = {};

sub _isin($@) {
	shift ~~ \@_;
}

sub _isuri(_) {
	shift =~ m|(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?|
}

register(share => sub($%) {
	my ($route, %options) = @_;
	unless (exists $routes->{$route}) {
		$routes->{$route} = [];
		if (ref $route) {
			my $prefl = Dancer::App->current->registry->add_route(Dancer::Route->new(
				method => 'options',
				code => sub {},
				options => $route->options,
				pattern => $route->pattern
			));
			$options{method} = uc($route->method);
			push @{ $routes->{$prefl} } => \%options;
		} else {
			options $route => sub {};
		}
	}
	push @{ $routes->{$route} } => \%options;
});

hook before => sub {
	my $route = shift || return;#croak "No argument defined for this hook";
	my $request = Dancer::SharedData->request;
	my $path = $request->path_info;
	
	return unless (exists $routes->{$path} or exists $routes->{$route});
	
	my $preflight = uc $request->method eq 'OPTIONS';
	
	my $origin            = scalar($request->header('Origin')) || return;
	return unless _isuri($origin);
	
	my $requested_method  = $preflight
	                      ? scalar($request->header('Access-Control-Request-Method'))
						  : $request->method
						  ;
	return unless defined $requested_method;
	my @requested_headers = map { s{\s+}{}g; $_ } split /,+/, (scalar($request->header('Access-Control-Request-Headers')) || '');
	
	my $ok = 0;
	my ($headers, $xoptions);
	
	$path = "$route" if exists $routes->{$route};
	
	RULE: foreach my $options (@{$routes->{$path}}) {
		$headers = {};
		if (exists $options->{origin}) {
			given (ref $options->{origin}) {
				when ('CODE') {
					next RULE if !$options->{origin}->(URI->new($origin));
				}
				when ('ARRAY') {
					next RULE unless _isin($origin => @{ $options->{origin} });
				}
				when ('Regexp') {
					next RULE unless $origin =~ $options->{origin};
				}
				when ('') {
					next RULE unless $options->{origin} eq $origin;
				}
				default {
					confess("unknown origin type: $_");
				}
			}
		} else {
			$origin = '*';
		}
		$headers->{'Access-Control-Allow-Origin'} = $origin;
		$headers->{'Vary'} = 'Origin' if $origin ne '*';

		
		if (exists $options->{credentials}) {
			if (!!$options->{credentials}) {
				if ($origin eq '*') {
					warning('The string "*" cannot be used for a resource that supports credentials.');
					next RULE;
				}
				$headers->{'Access-Control-Allow-Credentials'} = 'true' ;
			}
		}
		
		if (exists $options->{expose}) {
			$headers->{'Access-Control-Expose-Headers'} = $options->{expose};
		}
		
		if (exists $options->{methods}) {
			next unless _isin(lc $requested_method => map lc, @{ $options->{methods} });
			$headers->{'Access-Control-Allow-Methods'} = join ', ' => map uc, @{ $options->{methods} };
		} elsif (exists $options->{method}) {
			next unless $options->{method} eq $requested_method;
			$headers->{'Access-Control-Allow-Methods'} = $options->{method};
		}
		
		if (exists $options->{headers}) {
			foreach my $requested_header (@requested_headers) {
				next RULE unless _isin(lc $requested_header => map lc, @{ $options->{headers} });
			}
			$headers->{'Access-Control-Allow-Headers'} = join ', ' => @{ $options->{headers} };
		}

		if ($preflight and exists $options->{maxage}) {
			$headers->{'Access-Control-Max-Age'} = $options->{maxage};
		}
		
		$ok = 1;
		$xoptions = $options;
		last RULE;
	}

	if ($ok) {
		Dancer::SharedData->response->headers(%$headers);
		var(CORS => $xoptions);
	}
};

=head1 AUTHOR

David Zurborg, C<< <zurborg@cpan.org> >>

=head1 BUGS

Please report any bugs or feature requests trough my project management tool
at L<http://development.david-zurb.org/projects/libdancer-plugin-cors-perl/issues/new>.  I
will be notified, and then you'll automatically be notified of progress on
your bug as I make changes.

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc Dancer::Plugin::CORS

You can also look for information at:

=over 4

=item * Redmine: Homepage of this module

L<http://development.david-zurb.org/projects/libdancer-plugin-cors-perl>

=item * RT: CPAN's request tracker

L<http://rt.cpan.org/NoAuth/Bugs.html?Dist=Dancer-Plugin-CORS>

=item * AnnoCPAN: Annotated CPAN documentation

L<http://annocpan.org/dist/Dancer-Plugin-CORS>

=item * CPAN Ratings

L<http://cpanratings.perl.org/d/Dancer-Plugin-CORS>

=item * Search CPAN

L<http://search.cpan.org/dist/Dancer-Plugin-CORS/>

=back

=head1 COPYRIGHT & LICENSE

Copyright 2014 David Zurborg, all rights reserved.

This program is released under the following license: open-source

=cut

register_plugin;
1;

__END__

			if (exists $options->{methods}) {
				if (exists $options->{methods}->{$requested_method} and !$options->{methods}->{$requested_method}) {
					next;
				}
				$headers->{'Access-Control-Allow-Methods'} =
					join ', ' =>
					grep { !!$options->{methods}->{$_} }
					keys %{ $options->{methods} }
				;
			} else {
				$headers->{'Access-Control-Allow-Methods'} = $requested_method;
			}
			
			if (exists $options->{headers}) {
				if (exists $options->{headers}->{$requested_headers} and !$options->{headers}->{$requested_headers}) {
					next;
				}
				$headers->{'Access-Control-Allow-Headers'} =
					join ', ' =>
					grep { !!$options->{headers}->{$_} }
					keys %{ $options->{headers} }
				;
			} else {
				$headers->{'Access-Control-Allow-Headers'} = $requested_headers;
			}

