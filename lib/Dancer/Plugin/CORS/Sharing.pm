package Dancer::Plugin::CORS::Sharing;

=head2 new

=cut

sub new($%) {
	my $class = shift;
	my %options = (rules => [], @_);
	return bless \%options => ref $class || $class;
}

sub _add_rule($$%) {
	my ($self, $route, %options) = @_;
	$self->{_add_rule}->($route, %options);
}

=head2 rule

=cut

sub rule($%) {
	my ($self, %options) = @_;
	push @{$self->{rules}} => \%options;
}

=head2 addH

=cut

sub addH($%) {
	my ($self, %routes) = @_;
	foreach my $routes (values %routes) {
		$routes = [ $routes ] unless ref $routes eq 'ARRAY';
		foreach my $route (@$routes) {
			foreach my $options (@{$self->{rules}}) {
				$self->_add_rule($route, %$options);
			}
		}
	}
}

=head2 addA

=cut

sub addA($@) {
	my ($self, @routes) = @_;
	foreach my $routes (@routes) {
		$routes = [ $routes ] unless ref $routes eq 'ARRAY';
		foreach my $route (@$routes) {
			foreach my $options (@{$self->{rules}}) {
				$self->_add_rule($route, %$options);
			}
		}
	}
}

1;
