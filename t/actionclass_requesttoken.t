use Test::Base;
use File::Temp;

{
    package T1;
    use Ark;

    use_plugins qw/
        Session
        Session::State::Cookie
        Session::Store::Memory
        /;

    conf 'Plugin::Session::State::Cookie' => {
        cookie_expires => '+3d',
    };

    package T1::Model::Digest;
    use Ark 'Model::Adaptor';

    __PACKAGE__->config(
        class => 'Digest::SHA1',
    );

    package T1::Controller::Root;
    use Ark 'Controller';

    with 'Ark::ActionClass::RequestToken';

    has '+namespace' => default => '';

    sub get_session : Local {
        my ($self, $c) = @_;
        $c->res->body($c->session->get('_token'));
    }

    sub create : Local CreateToken {
        my ($self, $c) = @_;
        $c->res->body($c->session->get('_token'));
    }

    sub validate : Local ValidateToken {
        my ($self, $c) = @_;
        $c->res->body($self->is_valid_token);
    }

    sub remove : Local RemoveToken {
        my ($self, $c) = @_;
        $c->res->body($c->session->get('_token'));
    }

    sub m_create : Local {
        my ($self, $c) = @_;
        $self->create_token;
        $c->res->body($c->session->get('_token'));
    }

    sub m_validate : Local {
        my ($self, $c) = @_;
        $self->validate_token;
        $c->res->body($self->is_valid_token);
    }

    sub m_remove : Local {
        my ($self, $c) = @_;
        $self->remove_token;
        $c->res->body($c->session->get('_token'));
    }
}

plan 'no_plan';

use Ark::Test 'T1',
    components => [qw/Controller::Root Model::Digest/],
    reuse_connection => 1;

{
    is(get("/get_session"), '', 'token is not created yet');
    my $token = get('/create');
    is length($token), 40, 'assert token length';
    like $token, qr/^[0-9a-f]+$/, 'assert token regex';
    is(request(POST => "/validate", make_headers($token))->content, '1', 'token validate ok');
    is(get("/get_session"), '', 'token is removed');

    $token = get("/create");
    is length($token), 40, 'assert token length';
    is(get("/get_session"), $token, 'token is created');
    $token = get("/remove");
    is(get("/get_session"), '', 'token is removed');
}

{
    is(get("/get_session"), '', 'token is not created yet');
    my $token = get('/m_create');
    is length($token), 40, 'assert token length';
    like $token, qr/^[0-9a-f]+$/, 'assert token regex';
    is(request(POST => "/m_validate", make_headers($token))->content, '1', 'token validate ok');
    is(get("/get_session"), '', 'token is removed');

    $token = get("/m_create");
    is length($token), 40, 'assert token length';
    is(get("/get_session"), $token, 'token is created');
    $token = get("/m_remove");
    is(get("/get_session"), '', 'token is removed');
}

sub make_headers {
    my $token = shift;
    my $content = "_token=$token";
    my $headers = [
    'Content-Type'   => 'Content-Type: application/x-www-form-urlencoded',
    'Content-Length' => length $content,
    ];
    return ($headers, $content);
}