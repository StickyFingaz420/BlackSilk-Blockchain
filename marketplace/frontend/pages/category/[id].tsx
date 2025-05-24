import { GetStaticPaths, GetStaticProps } from 'next';
import { useRouter } from 'next/router';
import { fetchProducts } from '../../utils/nodeApi';
import { Product } from '../../types/product';

export default function CategoryPage({ products, id }: { products: Product[]; id: string }) {
  const router = useRouter();
  // TODO: Fetch products for this category from the node
  return (
    <main className="max-w-4xl mx-auto py-12 px-4">
      <h2 className="text-2xl font-bold mb-4">Category: {id}</h2>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {products.length > 0 ? (
          products.map((product) => (
            <div key={product.id} className="p-4 bg-white rounded shadow flex flex-col justify-between">
              <div>
                <div className="font-semibold text-lg mb-1">{product.title}</div>
                <div className="text-gray-600 mb-2 line-clamp-2">{product.description}</div>
              </div>
              <div className="flex items-center justify-between mt-2">
                <span className="font-bold">{product.price} BLK</span>
                <a href={`/product/${product.id}`} className="text-blue-600 hover:underline">
                  View
                </a>
              </div>
            </div>
          ))
        ) : (
          <div className="col-span-full text-center py-6">No products found in this category.</div>
        )}
      </div>
    </main>
  );
}

export const getStaticPaths: GetStaticPaths = async () => {
  // Fetch all categories from the node (stubbed for now)
  const categories = ['software', 'ebooks', 'services', 'physical'];
  return {
    paths: categories.map((id) => ({ params: { id } })),
    fallback: 'blocking',
  };
};

export const getStaticProps: GetStaticProps = async (context) => {
  const id = context.params?.id as string;
  try {
    const products = await fetchProducts(id);
    return { props: { products, id }, revalidate: 60 };
  } catch {
    return { props: { products: [], id } };
  }
};
