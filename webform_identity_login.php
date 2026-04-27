<?php

/**
 * @file
 */

use Drupal\webform_identity_login\CiviCRM\IdentityLoginTokens;
use Symfony\Component\DependencyInjection\Definition;

/**
 * Implémentation de hook_civicrm_container().
 */
function webform_identity_login_civicrm_container($container) {
  \Civi::log()->debug('CIVI CONTAINER HOOK OK');

  $definition = new Definition(
    IdentityLoginTokens::class
  );

  $definition->addTag('civi.token_subscriber');

  $container->setDefinition(
    'webform_identity_login.identity_login_tokens',
    $definition
  );
}
