package Dancer::Plugin::CORS;

use Modern::Perl;
use Dancer::Plugin::CORS::Sharing;

=head1 NAME

Dancer::Plugin::CORS - A plugin for using cross origin resource sharing

=head1 VERSION

Version 0.02

=cut

our $VERSION = '0.02';

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
use Scalar::Util qw(blessed);
use URI;

use constant DEBUG => 0;

my $routes = {};

sub _isin($@) {
	shift ~~ \@_;
}

sub _isuri(_) {
	shift =~ m|(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?(?:#(.*))?|
}

sub _handle;
my $current_route;

sub _prefl_handle {
	debug "[CORS] entered preflight request main subroutine" if DEBUG;
	unless (defined $current_route) {
		warning "[CORS] current route not defined!";
		return;
	}
	unless(_handle($current_route)) {
		my $request = Dancer::SharedData->request;
		while ($current_route = $current_route->next) {
			if ($current_route->match($request)) {
				debug "[CORS] going to next handler" if DEBUG;
				pass;
			}
        }
		debug "[CORS] no more rules." if DEBUG;
	}
	$current_route = undef;
}

sub _add_rule($%) {
	my ($route, %options) = @_;
	
	if (blessed $route and $route->isa('Dancer::Route')) {
		my $prefl = Dancer::App->current->registry->add_route(Dancer::Route->new(
			method => 'options',
			code => \&_prefl_handle,
			options => $route->options,
			pattern => $route->pattern
		));
		$options{method} = uc($route->method);
		$routes->{$prefl} = [{ %options }];
		debug "registered preflight route handler for ".$route->method." pattern: ".$route->pattern."\n" if DEBUG;
	}
	
	unless (exists $routes->{$route}) {
		$routes->{$route} = [];
		unless (ref $route) {
			debug "registered preflight route handler for any pattern: $route\n" if DEBUG;
			options $route => \&_prefl_handle;
		}
	}
	push @{ $routes->{$route} } => \%options;
}

sub _handle {
	my $route = shift;
	my $request = Dancer::SharedData->request;
	my $path = $request->path_info;
	
	unless (exists $routes->{$path} or exists $routes->{$route}) {
		debug "[CORS] path $path or route $route did not no matched any rule" if DEBUG;
	}
	
	my $preflight = uc $request->method eq 'OPTIONS';
	
	debug "[CORS] preflight request" if DEBUG and $preflight;
	
	my $origin = scalar($request->header('Origin'));
	
	unless (defined $origin) {
		debug "[CORS] no origin header present in request" if DEBUG;
		return;
	}

	unless (_isuri($origin)) {
		debug "[CORS] origin '$origin' is not a URI" if DEBUG;
		return;
	}
	
	my $requested_method  = $preflight
	                      ? scalar($request->header('Access-Control-Request-Method'))
						  : $request->method
						  ;
	unless (defined $requested_method) {
		debug "[CORS] no request method defined" if DEBUG;
	}

	my @requested_headers = map { s{\s+}{}g; $_ } split /,+/, (scalar($request->header('Access-Control-Request-Headers')) || '');
	
	my ($ok, $i) = (0, 0);
	my ($headers, $xoptions);
	
	if (exists $routes->{$route}) {
		$path = "$route";
		debug "[CORS] dynamic route" if DEBUG;
	} else {
		debug "[CORS] static route" if DEBUG;
	}
	
	my $n = scalar @{$routes->{$path}};
	
	RULE: foreach my $options (@{$routes->{$path}}) {
		debug "[CORS] testing rule ".++$i." of $n" if DEBUG;
		if (DEBUG) {
			use Data::Dumper;
			debug Dumper($options);
		}
		$headers = {};
		if (exists $options->{origin}) {
			given (ref $options->{origin}) {
				when ('CODE') {
					if (!$options->{origin}->(URI->new($origin))) {
						debug "[CORS] origin $origin did not matched against coderef" if DEBUG;
						next RULE;
					}
				}
				when ('ARRAY') {
					unless (_isin($origin => @{ $options->{origin} })) {
						debug "[CORS] origin $origin is not in array" if DEBUG;
						next RULE;
					}
				}
				when ('Regexp') {
					unless ($origin =~ $options->{origin}) {
						debug "[CORS] origin $origin did not matched against regexp" if DEBUG;
						next RULE;
					}
				}
				when ('') {
					unless ($options->{origin} eq $origin) {
						debug "[CORS] origin $origin did not matched against static string" if DEBUG;
						next RULE;
					}
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
					warning('For a resource that supports credentials a origin matcher must be specified.');
					next RULE;
				}
				$headers->{'Access-Control-Allow-Credentials'} = 'true' ;
			}
		}
		
		if (exists $options->{expose}) {
			$headers->{'Access-Control-Expose-Headers'} = $options->{expose};
		}
		
		if (exists $options->{methods}) {
			unless (_isin(lc $requested_method => map lc, @{ $options->{methods} })) {
				debug "[CORS] request method not allowed" if DEBUG;
				next RULE;
			}
			$headers->{'Access-Control-Allow-Methods'} = join ', ' => map uc, @{ $options->{methods} };
		} elsif (exists $options->{method}) {
			unless ($options->{method} eq $requested_method) {
				debug "[CORS] request method '$requested_method' not allowed: ".$options->{method} if DEBUG;
				next RULE;
			}
			$headers->{'Access-Control-Allow-Methods'} = $options->{method};
		}
		
		if (exists $options->{headers}) {
			foreach my $requested_header (@requested_headers) {
				unless (_isin(lc $requested_header => map lc, @{ $options->{headers} })) {
					debug "[CORS] requested headers did not match allowed in rule" if DEBUG;
					next RULE;
				}
			}
			$headers->{'Access-Control-Allow-Headers'} = join ', ' => @{ $options->{headers} };
		} elsif (@requested_headers) {
			$headers->{'Access-Control-Allow-Headers'} = join ', ' => @requested_headers;
		}

		if ($preflight and exists $options->{maxage}) {
			$headers->{'Access-Control-Max-Age'} = $options->{maxage};
		}
		
		$ok = 1;
		var CORS => {%$options};
		Dancer::SharedData->response->headers(%$headers);
		if (DEBUG) {
			use Data::Dumper;
			debug Dumper({headers => $headers});
		}
		last RULE;
	}

	if ($ok) {
		debug "[CORS] matched!" if DEBUG;
	} else {
		debug "[CORS] no rule matched" if DEBUG;
	}
	
	return $ok;
}

register(share => \&_add_rule);
hook(before => sub {
	$current_route = shift || return;
	my $preflight = uc Dancer::SharedData->request->method eq 'OPTIONS';
	if ($preflight) {
		debug "[CORS] pre-check: preflight request, handle within main subroutine" if DEBUG;
	} else {
		debug "[CORS] pre-check: no preflight, handle actual request now" if DEBUG;
		_handle($current_route);
	}
});

my $current_sharing;
register sharing => sub {
	my $class = __PACKAGE__.'::Sharing';
	$current_sharing ||= $class->new(@_,_add_rule=>\&_add_rule);
	return $current_sharing;
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
