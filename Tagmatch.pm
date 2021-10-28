package Mail::SpamAssassin::Plugin::Tagmatch;
my $VERSION = 0.30;

use strict;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Util qw(compile_regexp);
use List::Util ();

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

sub dbg { Mail::SpamAssassin::Plugin::dbg ("Tagmatch: @_"); }

sub uri_to_domain {
  my ($self, $domain) = @_;

  if ($Mail::SpamAssassin::VERSION <= 3.004000) {
    Mail::SpamAssassin::Util::uri_to_domain($domain);
  } else {
    $self->{main}->{registryboundaries}->uri_to_domain($domain);
  }
}

# constructor: register the eval rule
sub new
{
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule("check_tag_in_urilist");
  $self->register_eval_rule("check_tag_in_addrlist");

  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds = ();

  push (@cmds, { setting => 'tagmatch',
    code => sub {
      my ($conf, $key, $value, $line) = @_;
      my @values = split(/\s+/, $value);
      if (!defined $value || $value =~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      } elsif (@values != 4) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      } else {
        my ($rulename, $target, $equality, $compare) = @values;
        my $compare_tag;

        if ($equality eq '=~') {
          my ($rec, $err) = compile_regexp($compare, 1);
          if (!$rec) {
           dbg("config: invalid compare value '$value': $err");
           return $Mail::SpamAssassin::Conf::INVALID_VALUE;
          }
          $compare = $rec;

        } elsif ($equality =~ /^[\<=\>!]+$/) {
          $compare = $compare || 1;
        } elsif ($equality =~ /^(eq|ne)$/) {
          if ($compare =~ /^_([A-Z][A-Z0-9_]*)_$/) {
            $compare_tag = $1;
          }
        } else {
          return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        }

        $target =~ /^_([A-Z][A-Z0-9_]*)_$/;

        $conf->{parser}->{conf}->{tagmatch_rules}->{$rulename} = { target => $1, equal => $equality, compare => $compare, compare_tag => $compare_tag };
        $conf->{parser}->add_test($rulename, undef, $Mail::SpamAssassin::Conf::TYPE_EMPTY_TESTS);

      }

   }});

  $conf->{parser}->register_commands(\@cmds);
}

sub extract_metadata {
  my($self, $opts) = @_;
  my $pms = $opts->{permsgstatus};
  my $conf = $pms->{conf};

  foreach my $rulename (sort(keys %{$conf->{tagmatch_rules}})) {
    my @tag_dep = ($conf->{tagmatch_rules}->{$rulename}->{target});
    push @tag_dep, $conf->{tagmatch_rules}->{$rulename}->{compare_tag} if $conf->{tagmatch_rules}->{$rulename}->{compare_tag};

    $pms->action_depends_on_tags(\@tag_dep,
      sub { my($pms,@args) = @_;
        $self->check_tagmatch($pms,$rulename) }
    );

    dbg("Callback for $conf->{tagmatch_rules}->{$rulename}->{target} added.");
  }

}

sub check_tagmatch {
  my ($self, $pms, $rulename) = @_;

  my $compare = $pms->{conf}->{tagmatch_rules}->{$rulename}->{compare};
  my $equality = $pms->{conf}->{tagmatch_rules}->{$rulename}->{equal};
  my $target = $pms->{conf}->{tagmatch_rules}->{$rulename}->{target};
  my $tag = $pms->get_tag($target);

  if ($pms->{conf}->{tagmatch_rules}->{$rulename}->{compare_tag}) {
    $compare = $pms->get_tag($pms->{conf}->{tagmatch_rules}->{$rulename}->{compare_tag});
  }

  return unless ($tag);

  my $match = 0;
  dbg("Rule $rulename. Checking tag $target $tag $equality $compare");

  if ($equality eq '=~') {
    $match = 1 if $tag =~ $compare;
  } elsif ($equality =~ /^[\<=\>!]+$/) {
    if ($equality eq '<') {
      $match = 1 if $tag < $compare;
    } elsif ($equality eq '>') {
      $match = 1 if $tag > $compare;
    } elsif ($equality eq '<=') {
      $match = 1 if $tag <= $compare;
    } elsif ($equality eq '>=') {
      $match = 1 if $tag >= $compare;
    } elsif ($equality eq '==') {
      $match = 1 if $tag == $compare;
    } else {
      $match = 1 if $tag != $compare;
    }
  } elsif ($equality =~ /^(eq|ne)$/) {
    if ($equality eq 'eq') {
      $match = 1 if $tag eq $compare;
    } else {
      $match = 1 if $tag ne $compare;
    }
  }

  if ($match) {
    dbg("Rulename $rulename matched");
    $pms->got_hit($rulename, undef, ruletype => 'tagmatch');
  }

}

sub check_tag_in_urilist {

  my ($self, $pms, $tag, $list) = @_;
  my $rulename = $pms->get_current_eval_rule_name();

  $pms->action_depends_on_tags($tag,
      sub { my($pms,@args) = @_;
        $self->_urilist_callback($pms, $list, $tag, $rulename);
      }
  );

  return 0;

}

sub check_tag_in_addrlist {

  my ($self, $pms, $tag, $list) = @_;
  my $rulename = $pms->get_current_eval_rule_name();

  $pms->action_depends_on_tags($tag,
      sub { my($pms,@args) = @_;
        $self->_urilist_callback($pms, $list, $tag, $rulename);
      }
  );

  return 0;

}

sub _urilist_callback {
  my ($self, $pms, $list, $tag, $rulename) = @_;

  foreach my $addr (split / /, $pms->get_tag($tag) || '') {

    if ($self->_check_urilist ($list, lc $addr)) {
      $pms->got_hit($rulename, undef, ruletype => 'tagmatch');
    }

  }

}

sub _addrlist_callback {
  my ($self, $pms, $list, $tag, $rulename) = @_;

  foreach my $addr (split / /, $pms->get_tag($tag) || '') {

    if ($self->_check_addrlist ($list, lc $addr)) {
      $pms->got_hit($rulename, undef, ruletype => 'tagmatch');
    }

  }

}

sub _check_urilist {
  my ($self, $list, $uri) = @_;

  $uri = lc $uri;

  my $list_ref = $self->{main}{conf}{uri_host_lists}{$list};
  unless (defined $list_ref) {
    warn "eval: could not find list $list";
    return;
  }

  my %hosts;

  my($domain,$host) = $self->uri_to_domain($uri);

  local($1,$2);
  my @query_keys;
  if ($host =~ /^\[(.*)\]\z/) {  # looks like an address literal
    @query_keys = ( $1 );
  } elsif ($host =~ /^\d+\.\d+\.\d+\.\d+\z/) {  # IPv4 address
    @query_keys = ( $host );
  } elsif ($host ne '') {
    my($h) = $host;
    for (;;) {
      shift @query_keys  if @query_keys > 10;  # sanity limit, keep tail
      push(@query_keys, $h);  # sub.example.com, example.com, com
      last if $h !~ s{^([^.]*)\.(.*)\z}{$2}s;
    }
  }
  my $verdict;
  my $match;

  foreach my $q (@query_keys) {
    $verdict = $list_ref->{$q};
    if (defined $verdict) {
      $match = $q eq $host ? $host : "$host ($q)";
      $match = '!'  if !$verdict;
      last;
    }
  }

  if (defined $verdict) {
    dbg("rules: check_uri_host %s, (%s): %s, search: %s",
        $uri, $list, $match, join(', ',@query_keys));
  }

  $verdict;

}

sub _check_addrlist {
  my ($self, $list, $addr) = @_;

  my $list_ref = $self->{main}{conf}{$list};
  unless (defined $list_ref) {
    warn "eval: could not find list $list";
    return;
  }

  $addr = lc $addr;
  if (defined ($list_ref->{$addr})) { return 1; }
  study $addr;  # study is a no-op since perl 5.16.0, eliminating related bugs
  foreach my $regexp (values %{$list_ref}) {
    if ($addr =~ qr/$regexp/i) {
      dbg("rules: address $addr matches whitelist or blacklist regexp: $regexp");
      return 1;
    }
  }

  return 0;
}

1;
