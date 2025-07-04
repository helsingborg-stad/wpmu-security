<?php 

if (function_exists('acf_add_local_field_group')) {
    acf_add_local_field_group(array(
    'key' => 'group_686794bedb2eb',
    'title' => __('Additional Domains', 'wpmu-security'),
    'fields' => array(
        0 => array(
            'key' => 'field_686794bf6725d',
            'label' => __('Allowed Domains', 'wpmu-security'),
            'name' => 'security_csp_allowed_domains',
            'aria-label' => '',
            'type' => 'repeater',
            'instructions' => '',
            'required' => 0,
            'conditional_logic' => 0,
            'wrapper' => array(
                'width' => '',
                'class' => '',
                'id' => '',
            ),
            'acfe_repeater_stylised_button' => 0,
            'layout' => 'table',
            'pagination' => 0,
            'min' => 0,
            'max' => 0,
            'collapsed' => '',
            'button_label' => __('Add domain', 'wpmu-security'),
            'rows_per_page' => 20,
            'sub_fields' => array(
                0 => array(
                    'key' => 'field_68679b1075e68',
                    'label' => __('Category', 'wpmu-security'),
                    'name' => 'category',
                    'aria-label' => '',
                    'type' => 'select',
                    'instructions' => '',
                    'required' => 1,
                    'conditional_logic' => 0,
                    'wrapper' => array(
                        'width' => '50',
                        'class' => '',
                        'id' => '',
                    ),
                    'choices' => array(
                        'script-src' => __('script-src', 'wpmu-security'),
                        'style-src' => __('style-src', 'wpmu-security'),
                        'img-src' => __('img-src', 'wpmu-security'),
                        'media-src' => __('media-src', 'wpmu-security'),
                        'frame-src' => __('frame-src', 'wpmu-security'),
                        'object-src' => __('object-src', 'wpmu-security'),
                        'form-action' => __('form-action', 'wpmu-security'),
                        'font-src' => __('font-src', 'wpmu-security'),
                        'connect-src' => __('connect-src', 'wpmu-security'),
                    ),
                    'default_value' => false,
                    'return_format' => 'value',
                    'multiple' => 0,
                    'allow_null' => 0,
                    'ui' => 0,
                    'ajax' => 0,
                    'placeholder' => '',
                    'allow_custom' => 0,
                    'search_placeholder' => '',
                    'parent_repeater' => 'field_686794bf6725d',
                ),
                1 => array(
                    'key' => 'field_68679bef9922a',
                    'label' => __('Domain', 'wpmu-security'),
                    'name' => 'domain',
                    'aria-label' => '',
                    'type' => 'text',
                    'instructions' => __('You may use * in your domains to define wildcards.', 'wpmu-security'),
                    'required' => 0,
                    'conditional_logic' => 0,
                    'wrapper' => array(
                        'width' => '50',
                        'class' => '',
                        'id' => '',
                    ),
                    'default_value' => '',
                    'maxlength' => '',
                    'placeholder' => '',
                    'prepend' => '',
                    'append' => '',
                    'parent_repeater' => 'field_686794bf6725d',
                ),
            ),
        ),
        1 => array(
            'key' => 'field_6867d2420e437',
            'label' => __('Description of categories', 'wpmu-security'),
            'name' => '',
            'aria-label' => '',
            'type' => 'message',
            'instructions' => '',
            'required' => 0,
            'conditional_logic' => 0,
            'wrapper' => array(
                'width' => '',
                'class' => '',
                'id' => '',
            ),
            'message' => __('<table class="widefat striped">
    <thead>
        <tr>
            <th>Directive</th>
            <th>Description</th>
        </tr>
    </thead>
    <tbody>
        <tr>
            <td><code>script-src</code></td>
            <td>Load JavaScript files</td>
        </tr>
        <tr>
            <td><code>style-src</code></td>
            <td>Load CSS stylesheets</td>
        </tr>
        <tr>
            <td><code>img-src</code></td>
            <td>Load images</td>
        </tr>
        <tr>
            <td><code>media-src</code></td>
            <td>Load audio and video</td>
        </tr>
        <tr>
            <td><code>frame-src</code></td>
            <td>Load content in iframes</td>
        </tr>
        <tr>
            <td><code>object-src</code></td>
            <td>Load embedded objects (e.g. Flash, PDFs)</td>
        </tr>
        <tr>
            <td><code>form-action</code></td>
            <td>Allow forms to submit to domains</td>
        </tr>
        <tr>
            <td><code>font-src</code></td>
            <td>Load custom fonts</td>
        </tr>
        <tr>
            <td><code>connect-src</code></td>
            <td>Allow XHR/WebSocket/API connections</td>
        </tr>
    </tbody>
</table>', 'wpmu-security'),
            'new_lines' => 'wpautop',
            'esc_html' => 0,
        ),
    ),
    'location' => array(
        0 => array(
            0 => array(
                'param' => 'options_page',
                'operator' => '==',
                'value' => 'wpmu-security-settings',
            ),
        ),
    ),
    'menu_order' => 0,
    'position' => 'normal',
    'style' => 'default',
    'label_placement' => 'left',
    'instruction_placement' => 'label',
    'hide_on_screen' => '',
    'active' => true,
    'description' => '',
    'show_in_rest' => 0,
    'acfe_display_title' => '',
    'acfe_autosync' => array(
        0 => 'php',
        1 => 'json',
    ),
    'acfe_form' => 0,
    'acfe_meta' => '',
    'acfe_note' => '',
));
}