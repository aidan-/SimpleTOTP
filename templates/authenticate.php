<?php

/**
 * Template form for submitting 2fa codes
 *
 *
 */
assert('is_array($this->data["formData"])');
assert('is_string($this->data["formPost"])');

$this->data['head']  = '<link rel="stylesheet" type="text/css" href="/' .
    $this->data['baseurlpath'] . 'module.php/simpletotp/style.css" />' . "\n";

$this->includeAtTemplateBase('includes/header.php');
?>

<h1>Two-Factor Authentication Required</h1>
<p>You are required to enter your current two-factor authentication token using your configured
device to continue. <br />
If you are unsure what this means, or have your lost your two-factor authentication device, you
will need to contact your IT helpdesk for assistance.</p>
<?php
if (!is_null($this->data["userError"])) {
    ?>
    <div style="border-left: 1px solid #e8e8e8; border-bottom: 1px solid #e8e8e8; background: #f5f5f5">
        <img src="/<?php echo $this->data['baseurlpath']; ?>resources/icons/experience/gtk-dialog-error.48x48.png" class="float-l erroricon" style="margin: 15px " />
        <h2>Authentication Error</h2>
        <p><?php echo htmlspecialchars($this->data["userError"]); ?> </p>
    </div>
<?php
}
?>
<form style="display: inline; margin: 0px; padding: 0px" action="<?php echo
    htmlspecialchars($this->data['formPost']); ?>">

    <?php
    // Embed hidden fields...
    foreach ($this->data['formData'] as $name => $value) {
        echo '<input type="hidden" name="' . htmlspecialchars($name) .'" value="' . htmlspecialchars($value) . '" />';
    }
    ?>

    <label for="code">TOTP Code:</label>
    <input name="code" />
    <input type="submit" value="Submit" />
</form>

<?php
$this->includeAtTemplateBase('includes/footer.php');
