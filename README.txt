Pour résumer ce qui a été nécessaire pour corriger le tri des champs composites webform dans Views :
3 corrections combinées dans webform_identity_login.module :

hook_views_query_alter — corrige les JOINs buggés (property = 'x' AND property = '') via ReflectionClass sur tableQueue, et filtre MAX(sid) GROUP BY email pour dédupliquer.
WebformSubmissionFieldSortFixed (plugin sort) + hook_views_plugins_sort_alter — remplace le plugin sort vide de webform_views par un JOIN propre sur webform_submission_data avec webform_id, name, property, delta corrects.
hook_views_pre_render — retrie $view->result via usort sur les colonnes wsd_sort_fixed_*, car Views réordonne les résultats par sid après le chargement des entités, écrasant l'ORDER BY SQL.