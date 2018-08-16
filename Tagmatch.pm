package Mail::SpamAssassin::Plugin::Tagmatch;
my $VERSION = 0.14;

use strict;
use Mail::SpamAssassin::Plugin;
use List::Util ();

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

sub dbg { Mail::SpamAssassin::Plugin::dbg ("Tagmatch: @_"); }

# constructor: register the eval rule
sub new
{
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

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

        if ($equality eq '=~') {
          return $Mail::SpamAssassin::Conf::INVALID_VALUE unless $conf->{parser}->is_delimited_regexp_valid($rulename, $compare);
          return $Mail::SpamAssassin::Conf::INVALID_VALUE unless $compare =~ m{^/(.+)/([a-z]*)\z}xs;

          $compare = $2 ne '' ? qr{(?$2)$1} : qr{$1};

        } elsif ($equality =~ /^[\<=\>!]+$/) {
          $compare = sprintf("%d", $compare);
        } else {
          return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        }

        $target =~ /^_([A-Z][A-Z0-9_]*)_$/;

        $conf->{parser}->{conf}->{tagmatch_rules}->{$rulename} = { target => $1, equal => $equality, compare => $compare };
        $conf->{parser}->add_test($rulename, undef, $Mail::SpamAssassin::Conf::TYPE_EMPTY_TESTS);

      }

   }});

  $conf->{parser}->register_commands(\@cmds);
}

sub extract_metadata {
  my($self, $opts) = @_;
  my $pms = $opts->{permsgstatus};
  my $conf = $pms->{conf};

  foreach my $rulename (sort(keys $conf->{tagmatch_rules})) {
    $pms->action_depends_on_tags($conf->{tagmatch_rules}->{$rulename}->{target},
      sub { my($pms,@args) = @_;
        $self->check_tagmatch($pms,$rulename) }
    );

    dbg("Callback for $conf->{tagmatch_rules}->{$rulename}->{target} added.");
  }

}

sub check_tagmatch {
  my ($self, $pms, $rulename) = @_;

  my $compare = $pms->{conf}->{tagmatch_rules}->{$rulename}->{compare};
  my $equal = $pms->{conf}->{tagmatch_rules}->{$rulename}->{equal};
  my $target = $pms->{conf}->{tagmatch_rules}->{$rulename}->{target};
  my $tag = $pms->get_tag($target) || '';

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
  }

  if ($match) {
    dbg("Rulename $rulename matched");
    $pms->got_hit($rulename, undef, ruletype => 'tagmatch');
  }

}

1;
