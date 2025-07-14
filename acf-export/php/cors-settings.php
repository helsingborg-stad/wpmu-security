<?php 

if (function_exists('acf_add_local_field_group')) {
    acf_add_local_field_group(array(
    'key' => 'group_cors_settings',
    'title' => __('CORS Settings', 'wpmu-security'),
    'fields' => array(
        0 => array(
            'key' => 'field_cors_subdomain_support',
            'label' => __('Allow Subdomains', 'wpmu-security'),
            'name' => 'security_cors_subdomain_support',
            'aria-label' => '',
            'type' => 'true_false',
            'instructions' => __('Enable to automatically allow subdomains for the current domain. This will add wildcard subdomain support (e.g., if your site is example.com, this will allow *.example.com).', 'wpmu-security'),
            'required' => 0,
            'conditional_logic' => 0,
            'wrapper' => array(
                'width' => '',
                'class' => '',
                'id' => '',
            ),
            'message' => '',
            'default_value' => 0,
            'ui' => 1,
            'ui_on_text' => __('Yes', 'wpmu-security'),
            'ui_off_text' => __('No', 'wpmu-security'),
        ),
        1 => array(
            'key' => 'field_cors_domains',
            'label' => __('Allowed Origins', 'wpmu-security'),
            'name' => 'security_cors_allowed_domains',
            'aria-label' => '',
            'type' => 'repeater',
            'instructions' => __('Add domains that are allowed to make cross-origin requests to your site. These will be added to the Access-Control-Allow-Origin header.', 'wpmu-security'),
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
            'button_label' => __('Add origin', 'wpmu-security'),
            'rows_per_page' => 20,
            'sub_fields' => array(
                0 => array(
                    'key' => 'field_cors_domain',
                    'label' => __('Domain', 'wpmu-security'),
                    'name' => 'domain',
                    'aria-label' => '',
                    'type' => 'text',
                    'instructions' => __('Enter the domain without protocol (e.g., "example.com"). Use * for wildcards (e.g., "*.example.com").', 'wpmu-security'),
                    'required' => 1,
                    'conditional_logic' => 0,
                    'wrapper' => array(
                        'width' => '',
                        'class' => '',
                        'id' => '',
                    ),
                    'default_value' => '',
                    'maxlength' => 253,
                    'placeholder' => __('example.com', 'wpmu-security'),
                    'prepend' => '',
                    'append' => '',
                    'parent_repeater' => 'field_cors_domains',
                ),
            ),
        ),
        2 => array(
            'key' => 'field_cors_description',
            'label' => __('CORS Information', 'wpmu-security'),
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
            'message' => __('<p><strong>Cross-Origin Resource Sharing (CORS)</strong> allows web pages from other domains to access resources on your site.</p>
<p><strong>Current Domain:</strong> The current domain is always allowed for CORS requests.</p>
<p><strong>Allow Subdomains:</strong> When enabled, this adds wildcard subdomain support for the current domain (e.g., if your site is example.com, this will allow *.example.com).</p>
<p><strong>Additional Origins:</strong> You can add additional trusted domains below that should be allowed to make CORS requests.</p>
<p><strong>Security Note:</strong> Only add domains you trust. CORS origins allow other websites to make requests to your site on behalf of users.</p>', 'wpmu-security'),
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
    'menu_order' => 1,
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