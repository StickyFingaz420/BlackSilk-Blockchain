use zeroize::Zeroize;

pub fn secure_zeroize<T: Zeroize>(data: &mut T) {
    data.zeroize();
}
