use strict;
use warnings;
package Dancer::Plugin::CORS::Sharing;
# ABSTRACT: Helper class for I<sharing> method

use Carp;
use Scalar::Util qw(blessed);

# VERSION

=head1 DESCRIPTION

In order to use many rules with many routes, this helpers class helps you to organize yourself.

=head1 SYNOPSIS

    use Dancer::Plugin::CORS;

	sharing->rule(
		origin => ...,
		credentials => 1
	);
	
	$route = post '/' => sub { ... };
	
	sharing->add($route);

=method new

A convient way is to use the implicit form of the module. This means you don't have to call new() self, just start with defining rules and add routes.

When you want more than one ruleset, obtain a new instance by calling new():

	my $sharing = sharing->new;
	$sharing->rule(...);
	$sharing->add(...);
	
=cut

sub new {
	my $class = shift;
	my %options = (rules => []);
	if (blessed $class and $class->isa(__PACKAGE__)) {
		%options = (%$class, %options);
	}
	%options = (%options, @_);
	croak "sharing->new should be called inside a dancer app, not outside" unless exists $options{_add_rule};
	return bless \%options => ref $class || $class;
}

=method rule(%options)

This method defines a optionset. See L<Dancer::Plugin::CORS::share> for a explaination of valid options.

=cut

sub rule {
	my ($self, %options) = @_;
	push @{$self->{rules}} => \%options;
	$self;
}

=method add(@routes)

This method finally calls L<Dancer::Plugin::CORS::share> for any route. @routes maybe a list of arrayrefs of L<Dancer::Route> objects or paths.

Note: L<Dancer::Plugin::CRUD::resource> returns a hash instead of a list. Use values() to obtain the route objects:

	sharing->add(values(resource(...)));

=cut

sub add {
	my ($self, @routes) = @_;
	foreach my $routes (@routes) {
		$routes = [ $routes ] unless ref $routes eq 'ARRAY';
		foreach my $route (@$routes) {
			foreach my $options (@{$self->{rules}}) {
				$self->{_add_rule}->($route, %$options);
			}
		}
	}
	$self;
}

=method clear

This method clears all previously defined rules.

=cut

sub clear {
	my $self = shift;
	$self->{rules} = [];
	$self;
}

=head1 SEE ALSO

=over

=item * L<Dancer::Plugin::CORS>

=back

1;
