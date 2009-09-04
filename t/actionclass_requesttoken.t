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

    package T1::Model::Digest;
    use Ark 'Model::Adaptor';

    __PACKAGE__->config(
        class => 'Digest::SHA1',
    );

    package T1::Controller::Root;
    use Ark 'Controller';

    with 'Ark::ActionClass::RequestToken';

    __PACKAGE__->config->{namespace} = '';

    sub create :Path {
        my ($self, $c) = @_;
        $c->res->body('token created');
    }
}

plan 'no_plan';

use Ark::Test 'T1',
    components => [qw/Controller::Root
                      Model::Digest
                     /],
    reuse_connection => 1;

is(get('/create'), 'token created', 'token create ok');
