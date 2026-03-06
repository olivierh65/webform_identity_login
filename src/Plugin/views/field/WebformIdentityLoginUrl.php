<?php

namespace Drupal\webform_identity_login\Plugin\views\field;

use Drupal\Core\Url;
use Drupal\views\ResultRow;

/**
 * Provides the identity login URL with token.
 *
 * @ViewsField("webform_identity_login_url")
 */
class WebformIdentityLoginUrl extends WebformIdentityToken {

  /**
   * {@inheritdoc}
   */
  public function render(ResultRow $values) {
    $submission = $this->getEntity($values);

    if (!$submission) {
      return '';
    }

    $infos = $this->getNeededInfos($submission);

    if (!$infos['idtoken']) {
      return '';
    }

    $webform_id = $submission->getWebform()->id();

    $url = Url::fromRoute('entity.webform.canonical', [
      'webform' => $webform_id,
    ], [
      'query' => [
        'idtoken' => $infos['idtoken'],
        'cid' => $infos['cid'],
        'first_name' => $infos['first_name'],
        'last_name' => $infos['last_name'],
        'email' => $infos['email'],
        'phone' => $infos['phone'],
      ],
      'absolute' => TRUE,
    ]);

    return $url->toString();
  }

}
