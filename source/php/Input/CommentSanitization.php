<?php

namespace WPMUSecurity\Input;

use WpService\WpService;

class CommentSanitization {
    public function __construct(private WpService $wpService) {}

    /**
     * Adds hooks for comment sanitization.
     *
     * @return void
     */
    public function addHooks(): void
    {
        $this->wpService->addFilter('pre_comment_content', array($this, 'sanitizeCommentContent'), 10, 1);
    }

    public function sanitizeCommentContent(string $content): string {
        return htmlentities($content, ENT_QUOTES, 'UTF-8');
    }
}