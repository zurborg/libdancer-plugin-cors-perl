package Dancer::Plugin::CORS::Sharing;

use Modern::Perl;
use Scalar::Util qw(blessed);

=head1 NAME

Dancer::Plugin::CORS::Sharing - Helper class for I<sharing> keyword

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';

=head1 DESCRIPTION

...

=head1 SYNOPSIS

    use Dancer::Plugin::CORS;

	sharing->rule(
		origin => ...,
		credentials => 1
	);
	
	$route = post '/' => sub { ... };
	
	sharing->add($route);

=head1 METHODS
	
=head2 new

=cut

sub new($%) {
	my $class = shift;
	if (blessed $class and !@_) {
		$class->{rules} = [];
		return $class;
	}
	my %options = (rules => [], @_);
	return bless \%options => ref $class || $class;
}

=head2 rule

=cut

sub rule($%) {
	my ($self, %options) = @_;
	push @{$self->{rules}} => \%options;
}

=head2 add

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
}

=head1 AUTHOR

David Zurborg, C<< <zurborg@cpan.org> >>

=head1 SEE ALSO

=over

=item L<Dancer::Plugin::CORS>

=back

=head1 COPYRIGHT & LICENSE

Copyright 2014 David Zurborg, all rights reserved.

This program is released under the following license: open-source

=cut

1;
