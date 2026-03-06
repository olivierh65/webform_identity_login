<?php

namespace Drupal\webform_identity_login\Plugin\views\field;

use Drupal\views\Plugin\views\field\FieldPluginBase;
use Drupal\views\ResultRow;

use Drupal\webform_identity_login\Utils\HmacUtils;

/**
 * Provides computed identity token information.
 *
 * @ViewsField("webform_identity_token")
 */
class WebformIdentityToken extends FieldPluginBase {

  /**
   * Override query() to prevent Views from adding this field to the SQL query.
   * This is a computed field with no corresponding database column.
   */
  public function query() {
    // Do nothing — this field is computed in PHP, not from the database.
  }

  /**
   * Renders the webform identity token.
   */
  public function render(ResultRow $values) {

    $submission = $this->getEntity($values);

    if (!$submission) {
      return '';
    }

    $infos = $this->getNeededInfos($submission);

    return $infos['idtoken'];
  }

  /**
   * Retreive datas needded to compute token.
   */
  protected function getNeededInfos($submission) {
    $secret_key = NULL;
    $elements = $submission->getWebform()->getElementsInitializedAndFlattened();

    foreach ($elements as $key => $element) {
      if (($element['#type'] ?? NULL) === 'identity_login_composite') {
        $secret_key = $element['#secret_key'] ?? NULL;
        $identity_key = $element['#webform_key'] ?? '';
        break;
      }
    }
    $values = $submission->getData();
    $token = HmacUtils::computeHmac($values[$identity_key]['cid'] ?? 'Non trouve',
        $values[$identity_key]['first_name'] ?? '',
        $values[$identity_key]['last_name'] ?? '',
        $values[$identity_key]['email'] ?? '',
        $secret_key ?? '');
    return [
      'secret_key' => $secret_key,
      'idtoken' => $token,
      'first_name' => $values[$identity_key]['first_name'] ?? '',
      'last_name' => $values[$identity_key]['last_name'] ?? '',
      'email' => $values[$identity_key]['email'] ?? '',
      'phone' => $values[$identity_key]['phone'] ?? '',
      'cid' => $values[$identity_key]['cid'] ?? '',
    ];

  }

}
