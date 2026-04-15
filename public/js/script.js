// Common JavaScript functions

document.addEventListener('DOMContentLoaded', function() {
    // Add to cart functionality
    document.querySelectorAll('.add-to-cart').forEach(btn => {
        btn.addEventListener('click', function() {
            const form = this.closest('form');
            if (form) {
                alert('Produk ditambahkan ke keranjang!');
            }
        });
    });
    
    // Wishlist toggle
    document.querySelectorAll('.wishlist-btn').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            this.classList.toggle('active');
        });
    });
});

function addToCart(productId) {
    const quantity = document.getElementById('quantity')?.value || 1;
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = '/TubesPWEB/cart/add';
    form.innerHTML = `
        <input type="hidden" name="product_id" value="${productId}">
        <input type="hidden" name="quantity" value="${quantity}">
    `;
    document.body.appendChild(form);
    form.submit();
}
