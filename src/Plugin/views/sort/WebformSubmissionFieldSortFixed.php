<?php

namespace Drupal\webform_identity_login\Plugin\views\sort;

use Drupal\views\Plugin\views\sort\SortPluginBase;
use Drupal\views\Views;

/**
 * Remplace webform_submission_field_sort — corrige le JOIN composite buggé.
 *
 * Le plugin original hérite de SortPluginBase sans surcharger query(),
 * ce qui déclenche ensureMyTable() → JOIN avec property = 'x' AND property = ''.
 */
class WebformSubmissionFieldSortFixed extends SortPluginBase {

  /**
   * {@inheritdoc}
   */
  public function query() {
    $parsed = $this->parseWebformTable($this->table);

    /* \Drupal::logger('webform_identity_login')->debug(
    'WebformSubmissionFieldSortFixed::query table=@table parsed=@parsed alias=@alias',
    [
    '@table'  => $this->table,
    '@parsed' => print_r($parsed, TRUE),
    '@alias'  => 'wsd_sort_fixed_' . md5($this->table),
    ]
    ); */

    if (!$parsed) {
      // Champ simple (pas de composite) — comportement par défaut correct.
      $this->ensureMyTable();
      $this->query->addOrderBy($this->tableAlias, $this->realField, $this->options['order']);
      return;
    }

    // Composite : générer un JOIN propre sans la double condition property.
    $alias = 'wsd_sort_fixed_' . md5($this->table);

    $join = Views::pluginManager('join')->createInstance('standard', [
      'type'       => 'LEFT',
      'table'      => 'webform_submission_data',
      'field'      => 'sid',
      'left_table' => 'webform_submission',
      'left_field' => 'sid',
      'extra'      => [
        ['field' => 'webform_id', 'value' => $parsed['webform_id']],
        ['field' => 'name', 'value' => $parsed['name']],
        ['field' => 'property', 'value' => $parsed['property']],
        ['field' => 'delta', 'value' => '0'],
      ],
      'adjusted' => TRUE,
    ]);

    $this->query->addRelationship($alias, $join, 'webform_submission_data');
    $this->query->addOrderBy($alias, 'value', $this->options['order']);
  }

  /**
   * Parse le nom de table Views pour extraire webform_id, name, property.
   *
   * Format: webform_submission_field_{webform_id}_{name}__{property}
   * Séparateur composite : double underscore '__'.
   */
  protected function parseWebformTable(string $table): ?array {
    $prefix = 'webform_submission_field_';
    if (!str_starts_with($table, $prefix)) {
      return NULL;
    }

    $rest = substr($table, strlen($prefix));

    // Pas de double underscore = champ simple, pas un composite.
    if (!str_contains($rest, '__')) {
      return NULL;
    }

    $dpos = strrpos($rest, '__');
    $property = substr($rest, $dpos + 2);
    $before_property = substr($rest, 0, $dpos);

    $webform_id = $this->getWebformIdFromView();
    if (!$webform_id) {
      return NULL;
    }

    $wf_prefix = $webform_id . '_';
    if (!str_starts_with($before_property, $wf_prefix)) {
      return NULL;
    }

    $name = substr($before_property, strlen($wf_prefix));

    return [
      'webform_id' => $webform_id,
      'name'       => $name,
      'property'   => $property,
    ];
  }

  /**
   * Récupère le webform_id depuis le filtre bundle de la vue courante.
   */
  protected function getWebformIdFromView(): string {
    foreach ($this->view->filter ?? [] as $filter_id => $filter) {
      if (
        ($filter_id === 'webform_id' || ($filter->field ?? '') === 'webform_id')
        && isset($filter->value)
        && is_array($filter->value)
      ) {
        $keys = array_keys($filter->value);
        return reset($keys) ?: '';
      }
    }
    return '';
  }

}
