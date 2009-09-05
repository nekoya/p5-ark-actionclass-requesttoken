package Ark::ActionClass::RequestToken;
our $VERSION = '0.0.1';
use Mouse::Role;

has request_token_ident => (
    is      => 'rw',
    isa     => 'Str',
    lazy    => 1,
    default => sub { '__' . ref( $_[0] ) . '_token' },
);

has request_token_stash_name => (
    is      => 'rw',
    isa     => 'Str',
    lazy    => 1,
    default => sub {
        shift->class_config->{ stash_name }
            || '_token'
    },
);

has request_token_session_name => (
    is      => 'rw',
    isa     => 'Str',
    lazy    => 1,
    default => sub {
        shift->class_config->{ session_name }
            || '_token'
    },
);

has request_token_request_name => (
    is      => 'rw',
    isa     => 'Str',
    lazy    => 1,
    default => sub {
        shift->class_config->{ request_name }
            || '_token'
    },
);

has request_token_digest_model => (
    is      => 'rw',
    isa     => 'Object',
    lazy    => 1,
    default => sub {
        my $self  = shift;
        my $model = $self->app->model($self->class_config->{ digest_model })
            || $self->app->model('Digest');
    },
);

has request_token_password_pre_salt => (
    is      => 'rw',
    isa     => 'Str',
    lazy    => 1,
    default => sub {
        my $self = shift;
        $self->class_config->{ password_pre_salt } || '';
    },
);

has request_token_password_post_salt => (
    is      => 'rw',
    isa     => 'Str',
    lazy    => 1,
    default => sub {
        my $self = shift;
        $self->class_config->{ password_post_salt } || '';
    },
);

before ACTION => sub {
    my ($self, $action, @args) = @_;
    for my $key ( qw/CreateToken ValidateToken RemoveToken/ ) {
        (my $method = lc $key) =~ s/token$/_token/;
        $self->$method if $action->attributes->{ $key };
    }
};

no Mouse::Role;

sub create_token {
    my ($self) = @_;
    my $c = $self->context;

    my $digest = $self->request_token_digest_model;
    my $seed = join(time, rand(10000));
    $digest->add($self->request_token_password_pre_salt);
    $digest->add($seed);
    $digest->add($self->request_token_password_post_salt);
    my $hashed = $digest->hexdigest;

    $c->session->set($self->request_token_session_name, $hashed);
    $c->stash->{ $self->request_token_stash_name } = $hashed;
    $c->log(debug => "create token: $hashed");
}

sub validate_token {
    my ($self) = @_;
    my $c = $self->context;

    my $ses = $c->session->get($self->request_token_session_name) || '';
    unless ( $ses ) {
        $c->log(debug => "token is not stored");
        return;
    }

    my $req = $c->req->param($self->request_token_request_name)  || '';
    my $ident = $ses eq $req;
    $c->session->set($self->request_token_ident, $ident);
    $c->log(debug =>
        "validate token: $ses - $req : ".
        ($ident ? "passed" : "failed")
    );
    $self->remove_token;
}

sub remove_token {
    my ($self) = @_;
    my $c = $self->context;
    $c->session->remove($self->request_token_session_name);
    $c->log(debug => 'remove token');
}

sub is_valid_token {
    my ($self) = @_;
    return $self->context->session->get($self->request_token_ident);
}

sub _parse_CreateToken_attr {
    my ($self, $name, $value) = @_;
    return CreateToken => $value;
}

sub _parse_ValidateToken_attr {
    my ($self, $name, $value) = @_;
    return ValidateToken => $value;
}

sub _parse_RemoveToken_attr {
    my ($self, $name, $value) = @_;
    return RemoveToken => $value;
}

1;
__END__

=head1 NAME

Ark::ActionClass::RequestToken

=head1 SYNOPSIS

*use RequestToken
in your controller
    package MyApp::Controller::Login;
    use Ark 'Controller';
    with 'Ark::ActionClass::RequestToken';

*create token
set action attribute
    sub index : Path CreateToken {
or call manually
    $self->create_token;

*validate token
set action attribute
    sub login : Path ValidateToken {
or call manually
    $self->validate_token;
token will be removed after validate it.

*remove token
set action attribute
    sub loggedin : Private RemoveToken {
or call manually
    $self->remove_token;
in most cases you don't have to remove token manually.

=head1 DESCRIPTION

=head1 BUGS AND LIMITATIONS

No bugs have been reported.

=head1 AUTHOR

Ryo Miyake  C<< <ryo.studiom@gmail.com> >>

=head1 LICENCE AND COPYRIGHT

Copyright (c) 2009, Ryo Miyake C<< <ryo.studiom@gmail.com> >>. All rights reserved.

This module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself. See L<perlartistic>.
