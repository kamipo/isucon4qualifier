package Isu4Qualifier::Web;

use strict;
use warnings;
use utf8;
use Kossy;
use DBIx::Sunny;
use Digest::SHA qw/ sha256_hex /;
use Data::Dumper;

sub config {
  my ($self) = @_;
  $self->{_config} ||= {
    user_lock_threshold => $ENV{'ISU4_USER_LOCK_THRESHOLD'} || 3,
    ip_ban_threshold => $ENV{'ISU4_IP_BAN_THRESHOLD'} || 10
  };
};

sub db {
  my ($self) = @_;
  my $host = $ENV{ISU4_DB_HOST} || '127.0.0.1';
  my $port = $ENV{ISU4_DB_PORT} || 3306;
  my $username = $ENV{ISU4_DB_USER} || 'root';
  my $password = $ENV{ISU4_DB_PASSWORD};
  my $database = $ENV{ISU4_DB_NAME} || 'isu4_qualifier';

  $self->{_db} ||= do {
    DBIx::Sunny->connect(
      "dbi:mysql:database=$database;host=$host;port=$port", $username, $password, {
        RaiseError => 1,
        PrintError => 0,
        AutoInactiveDestroy => 1,
        mysql_enable_utf8   => 1,
        mysql_auto_reconnect => 1,
      },
    );
  };
}

sub calculate_password_hash {
  my ($password, $salt) = @_;
  sha256_hex($password . ':' . $salt);
};

sub fetch_history {
  my ($self, $user_id, $ip) = @_;
  if ($user_id) { # login が users テーブルに無い場合は user_id=0 になるけど、ここではそういうレコード取る必要ないので、省いてる
    my $rows = $self->db->select_all(q{(
        SELECT 'user_id' AS name, count AS count, NULL AS ip, NULL AS created_at FROM last_login_failure_count_user_id WHERE user_id = ?
      ) UNION (
        SELECT 'ip', count, NULL, NULL FROM last_login_failure_count_ip WHERE ip = ?
      ) UNION (
          SELECT 'last', NULL, ip, created_at FROM last_login_success_user_id JOIN login_log ON last_login_success_user_id.login_log_id=login_log.id WHERE last_login_success_user_id.user_id = ?
      )},
      $user_id, $ip, $user_id,
    );

    my %hash = map {
      $_->{name} => $_
    } @{ $rows };
    \%hash;
  } else {
    my $log = $self->db->select_row('SELECT count FROM last_login_failure_count_ip WHERE ip = ?', $ip);
    return { ip => $log };
  }
}

sub attempt_login {
  my ($self, $login, $password, $ip) = @_;
  my $user = $self->db->select_row('SELECT * FROM users WHERE login = ?', $login);

  my $history = $self->fetch_history(($user ? $user->{id} : 0), $ip);

  if ($history->{ip} && $history->{ip}{count} && $history->{ip}{count} >= $self->config->{ip_ban_threshold}) {
    $self->login_log(0, $login, $ip, $user ? $user->{id} : undef);
    return undef, 'banned';
  }

  if ($history->{user_id} && $history->{user_id}{count} && $history->{user_id}{count} >= $self->config->{user_lock_threshold}) {
    $self->login_log(0, $login, $ip, $user->{id});
    return undef, 'locked';
  }

  if ($user && calculate_password_hash($password, $user->{salt}) eq $user->{password_hash}) {
    $self->login_log(1, $login, $ip, $user->{id});
    $user->{last_ip} = $history->{last}{ip};
    $user->{last_at} = $history->{last}{created_at};
    return $user, undef;
  }
  elsif ($user) {
    $self->login_log(0, $login, $ip, $user->{id});
    return undef, 'wrong_password';
  }
  else {
    $self->login_log(0, $login, $ip);
    return undef, 'wrong_login';
  }
};

sub banned_ips {
  my ($self) = @_;
  my @ips;
  my $threshold = $self->config->{ip_ban_threshold};

  # ログイン成功した事がない ip address だけを絞り込む
  my $not_succeeded = $self->db->select_all('SELECT ip FROM (SELECT ip, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY ip) AS t0 WHERE t0.max_succeeded = 0 AND t0.cnt >= ?', $threshold);

  foreach my $row (@$not_succeeded) {
    push @ips, $row->{ip};
  }

  my $rows = $self->db->select_all('SELECT login_log.ip, COUNT(1) AS cnt FROM login_log INNER JOIN (SELECT ip, login_log_id FROM last_login_success_ip) AS t ON t.ip = login_log.ip WHERE succeeded = 0 AND login_log_id < id GROUP BY login_log.ip');

  for my $row (@$rows) {
      push @ips, $row->{ip} if ($threshold <= $row->{cnt});
  }
  \@ips;
};

sub locked_users {
  my ($self) = @_;
  my @user_ids;
  my $threshold = $self->config->{user_lock_threshold};

  # (login id が正しいもので)ログイン成功しなかったユーザを返す
  my $not_succeeded = $self->db->select_all('SELECT user_id, login FROM (SELECT user_id, login, MAX(succeeded) as max_succeeded, COUNT(1) as cnt FROM login_log GROUP BY user_id) AS t0 WHERE t0.user_id != 0 AND t0.max_succeeded = 0 AND t0.cnt >= ?', $threshold);
  # my $not_succeeded = $self->db->select_all('SELECT login_log.login, count(1) AS cnt FROM login_log LEFT OUTER JOIN last_login_success_user_id ON last_login_success_user_id.user_id = login_log.user_id WHERE last_login_success_user_id.user_id = NULL GROUP BY login_log.user_id');

  foreach my $row (@$not_succeeded) {
      push @user_ids, $row->{login};
  #     push @user_ids, $row->{login} if ($threshold <= $row->{cnt})
  }

  # thresholdにひっかかったユーザ
  my $rows = $self->db->select_all('SELECT login_log.login, COUNT(1) AS cnt FROM login_log INNER JOIN (SELECT user_id, login_log_id FROM last_login_success_user_id) AS t ON t.user_id = login_log.user_id WHERE succeeded = 0 AND login_log_id < id GROUP BY login_log.user_id');

  for my $row (@$rows) {
      push @user_ids, $row->{login} if ($threshold <= $row->{cnt})
  }
  \@user_ids;
};

sub login_log {
  my ($self, $succeeded, $login, $ip, $user_id) = @_;
  $self->db->query(
    'INSERT INTO login_log (`created_at`, `user_id`, `login`, `ip`, `succeeded`) VALUES (NOW(),?,?,?,?)',
    (defined $user_id ? $user_id : 0) , $login, $ip, ($succeeded ? 1 : 0)
  );
};

sub set_flash {
  my ($self, $c, $msg) = @_;
  $c->req->env->{'psgix.session'}->{flash} = $msg;
};

sub pop_flash {
  my ($self, $c, $msg) = @_;
  my $flash = $c->req->env->{'psgix.session'}->{flash};
  delete $c->req->env->{'psgix.session'}->{flash};
  $flash;
};

filter 'session' => sub {
  my ($app) = @_;
  sub {
    my ($self, $c) = @_;
    my $sid = $c->req->env->{'psgix.session.options'}->{id};
    $c->stash->{session_id} = $sid;
    $c->stash->{session}    = $c->req->env->{'psgix.session'};
    $app->($self, $c);
  };
};

get '/' => [qw(session)] => sub {
  my ($self, $c) = @_;

  $c->render('index.tx', { flash => $self->pop_flash($c) });
};

post '/login' => sub {
  my ($self, $c) = @_;
  my $msg;

  my ($user, $err) = $self->attempt_login(
    $c->req->param('login'),
    $c->req->param('password'),
    $c->req->address
  );

  if ($user && $user->{id}) {
    $c->req->env->{'psgix.session'}->{login}   = $user->{login};
    $c->req->env->{'psgix.session'}->{last_ip} = $user->{last_ip};
    $c->req->env->{'psgix.session'}->{last_at} = $user->{last_at};
    $c->redirect('/mypage');
  }
  else {
    if ($err eq 'locked') {
      $self->set_flash($c, 'This account is locked.');
    }
    elsif ($err eq 'banned') {
      $self->set_flash($c, "You're banned.");
    }
    else {
      $self->set_flash($c, 'Wrong username or password');
    }
    $c->redirect('/');
  }
};

get '/mypage' => [qw(session)] => sub {
  my ($self, $c) = @_;
  my $session = $c->req->env->{'psgix.session'};
  my $msg;

  if ($session->{login}) {
    $c->render('mypage.tx', { last_login => +{
        login      => $session->{login},
        ip         => $session->{last_ip},
        created_at => $session->{last_at},
    } });
  }
  else {
    $self->set_flash($c, "You must be logged in");
    $c->redirect('/');
  }
};

get '/report' => sub {
  my ($self, $c) = @_;
  $c->render_json({
    banned_ips => $self->banned_ips,
    locked_users => $self->locked_users,
  });
};

1;
