import React from 'react';

const Homepage = () => {
  return (
    <div className="container mx-auto p-4">
      <h1 className="text-3xl font-bold mb-4">Welcome to BlackSilk Marketplace</h1>
      <p className="text-lg">Explore categories and featured products below:</p>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
        {/* Example categories */}
        <div className="p-4 border rounded shadow">
          <h2 className="text-xl font-semibold">Software</h2>
          <p>Apps, tools, and more.</p>
        </div>
        <div className="p-4 border rounded shadow">
          <h2 className="text-xl font-semibold">E-books</h2>
          <p>Books and learning materials.</p>
        </div>
        <div className="p-4 border rounded shadow">
          <h2 className="text-xl font-semibold">Services</h2>
          <p>Consulting, courses, and more.</p>
        </div>
      </div>
    </div>
  );
};

export default Homepage;
